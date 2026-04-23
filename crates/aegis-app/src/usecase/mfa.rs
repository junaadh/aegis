use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
use sha2::{Digest, Sha256};
use totp_rs::{Algorithm, Secret, TOTP};

use aegis_core::{
    Actor, AuditTarget, Metadata, NewAuditEntry, RecoveryCode, RecoveryCodeState, TotpCredential,
    UserId,
};

use crate::app::AegisApp;
use crate::crypto::{decrypt_totp_secret, encrypt_totp_secret};
use crate::dto::{RequestContext, TotpEnrollFinishCommand, TotpEnrollResult, TotpVerifyCommand};
use crate::error::AppError;
use crate::jobs::JobPayload;
use crate::ports::{
    AuditRepo, Cache, Clock, CredentialRepo, Hasher, IdGenerator, OutboxRepo, Repos,
    SessionRepo, TokenGenerator, TransactionRepos, UserRepo, WebAuthn, WebhookDispatcher,
};

impl<R, C, H, T, W, K, I, A> AegisApp<R, C, H, T, W, K, I, A>
where
    R: Repos,
    C: Cache,
    H: Hasher,
    T: TokenGenerator,
    W: WebhookDispatcher,
    K: Clock,
    I: IdGenerator,
    A: WebAuthn,
{
    pub async fn enroll_totp_start(
        &self,
        user_id: UserId,
    ) -> Result<TotpEnrollResult, AppError> {
        let user = self
            .deps
            .repos
            .users()
            .get_by_id(user_id)
            .await?
            .ok_or(AppError::NotFound("user"))?;
        let now = self.deps.clock.now();
        let secret = Secret::generate_secret();
        let secret_encoded = secret.to_encoded().to_string();
        let secret_bytes = secret
            .to_bytes()
            .map_err(|e| AppError::Infrastructure(format!("invalid generated totp secret: {e}")))?;
        let (secret_encrypted, nonce) = encrypt_totp_secret(self.policy(), &secret_bytes)?;

        let totp = build_totp(self, &secret_bytes, user.email.as_str())?;
        let qr_code_url = totp.get_url();

        let credential = match self.deps.repos.credentials().get_totp_by_user_id(user_id).await? {
            Some(mut existing) => {
                existing.rotate_secret_at(secret_encrypted, nonce, now);
                existing.disable_at(now);
                existing
            }
            None => TotpCredential {
                id: self.deps.ids.totp_cred_id(),
                user_id,
                secret_encrypted,
                nonce,
                algorithm: self.policy().totp.algorithm,
                digits: self.policy().totp.digits as i32,
                period: self.policy().totp.period as i32,
                enabled: false,
                created_at: now,
                updated_at: now,
            },
        };

        self.deps
            .repos
            .with_transaction(|mut tx| {
                let credential = credential.clone();
                async move {
                    let result = async {
                        if tx.credentials().get_totp_by_user_id(user_id).await?.is_some() {
                            tx.credentials().update_totp(&credential).await?;
                        } else {
                            tx.credentials().insert_totp(&credential).await?;
                        }
                        Ok::<_, AppError>(())
                    }
                    .await;
                    (tx, result)
                }
            })
            .await?;

        Ok(TotpEnrollResult {
            secret: secret_encoded,
            qr_code_url,
            recovery_codes: vec![],
        })
    }

    pub async fn enroll_totp_finish(
        &self,
        user_id: UserId,
        cmd: TotpEnrollFinishCommand,
        ctx: &RequestContext,
    ) -> Result<Vec<String>, AppError> {
        let mut credential = self
            .deps
            .repos
            .credentials()
            .get_totp_by_user_id(user_id)
            .await?
            .ok_or(AppError::NotFound("totp_credential"))?;

        let secret = decrypt_totp_secret(
            self.policy(),
            &credential.secret_encrypted,
            &credential.nonce,
        )?;
        let user = self
            .deps
            .repos
            .users()
            .get_by_id(user_id)
            .await?
            .ok_or(AppError::NotFound("user"))?;
        let totp = build_totp(self, &secret, user.email.as_str())?;
        if !totp
            .check_current(&cmd.code)
            .map_err(|e| AppError::Infrastructure(format!("failed to verify totp code: {e}")))?
        {
            return Err(AppError::InvalidCredentials);
        }

        let now = self.deps.clock.now();
        credential.enabled = true;
        credential.updated_at = now;
        let recovery_codes = self.generate_recovery_codes(user_id, now).await?;
        let ctx = ctx.clone();
        let email = user.email.as_str().to_owned();

        self.deps
            .repos
            .with_transaction(|mut tx| {
                let credential = credential.clone();
                let recovery_codes = recovery_codes.clone();
                let ctx = ctx.clone();
                async move {
                    let result = async {
                        tx.credentials().update_totp(&credential).await?;
                        tx.credentials().delete_recovery_codes_by_user_id(user_id).await?;
                        tx.credentials().insert_recovery_codes(&recovery_codes.0).await?;
                        tx.outbox()
                            .enqueue(&JobPayload::SendMfaEnrolledNotification {
                                user_id: user_id.as_uuid(),
                            })
                            .await?;
                        tx.audit()
                            .insert(&NewAuditEntry {
                                event_type: "user.totp.enrolled".to_owned(),
                                actor: Actor::User(user_id),
                                target: Some(AuditTarget {
                                    target_type: "user".to_owned(),
                                    target_id: Some(user_id.as_uuid()),
                                }),
                                ip_address: ctx.ip_address.clone(),
                                user_agent: ctx.user_agent.clone(),
                                request_id: ctx.request_id,
                                metadata: Metadata::new(&format!(r#"{{"email":"{}"}}"#, email)),
                                created_at: now,
                            })
                            .await?;
                        Ok::<_, AppError>(())
                    }
                    .await;
                    (tx, result)
                }
            })
            .await?;

        Ok(recovery_codes.1)
    }

    pub async fn verify_totp(
        &self,
        user_id: UserId,
        session_token_hash: [u8; 32],
        cmd: TotpVerifyCommand,
        ctx: &RequestContext,
    ) -> Result<(), AppError> {
        let credential = self
            .deps
            .repos
            .credentials()
            .get_totp_by_user_id(user_id)
            .await?
            .ok_or(AppError::NotFound("totp_credential"))?;
        if !credential.enabled {
            return Err(AppError::MfaRequired);
        }

        let session = self
            .deps
            .repos
            .sessions()
            .get_by_token_hash(&session_token_hash)
            .await?
            .ok_or(AppError::Unauthorized)?;
        if session.user_id() != Some(user_id) {
            return Err(AppError::Forbidden);
        }

        let secret = decrypt_totp_secret(
            self.policy(),
            &credential.secret_encrypted,
            &credential.nonce,
        )?;
        let user = self
            .deps
            .repos
            .users()
            .get_by_id(user_id)
            .await?
            .ok_or(AppError::NotFound("user"))?;
        let totp = build_totp(self, &secret, user.email.as_str())?;
        let valid_totp = totp
            .check_current(&cmd.code)
            .map_err(|e| AppError::Infrastructure(format!("failed to verify totp code: {e}")))?;

        let now = self.deps.clock.now();
        let redeemed_recovery_code = if valid_totp {
            None
        } else {
            let code_hash = hash_recovery_code(&cmd.code);
            let mut recovery = self
                .deps
                .repos
                .credentials()
                .get_recovery_code_by_hash(&code_hash)
                .await?
                .ok_or(AppError::InvalidCredentials)?;
            if recovery.user_id != user_id {
                return Err(AppError::Forbidden);
            }
            recovery
                .redeem_at(now)
                .map_err(|_| AppError::InvalidCredentials)?;
            Some(recovery)
        };

        let mut session = session.clone();
        session.mark_mfa_verified();
        session.touch_at(now);
        let ctx = ctx.clone();

        self.deps
            .repos
            .with_transaction(|mut tx| {
                let session = session.clone();
                let redeemed_recovery_code = redeemed_recovery_code.clone();
                let ctx = ctx.clone();
                async move {
                    let result = async {
                        tx.sessions().update(&session).await?;
                        if let Some(code) = redeemed_recovery_code {
                            tx.credentials().update_recovery_code(&code).await?;
                        }
                        tx.audit()
                            .insert(&NewAuditEntry {
                                event_type: "user.totp.verified".to_owned(),
                                actor: Actor::User(user_id),
                                target: Some(AuditTarget {
                                    target_type: "session".to_owned(),
                                    target_id: Some(session.id.as_uuid()),
                                }),
                                ip_address: ctx.ip_address.clone(),
                                user_agent: ctx.user_agent.clone(),
                                request_id: ctx.request_id,
                                metadata: Metadata::empty(),
                                created_at: now,
                            })
                            .await?;
                        Ok::<_, AppError>(())
                    }
                    .await;
                    (tx, result)
                }
            })
            .await
    }

    pub async fn regenerate_recovery_codes(
        &self,
        user_id: UserId,
        ctx: &RequestContext,
    ) -> Result<Vec<String>, AppError> {
        let credential = self
            .deps
            .repos
            .credentials()
            .get_totp_by_user_id(user_id)
            .await?
            .ok_or(AppError::NotFound("totp_credential"))?;
        if !credential.enabled {
            return Err(AppError::MfaRequired);
        }

        let now = self.deps.clock.now();
        let recovery_codes = self.generate_recovery_codes(user_id, now).await?;
        let ctx = ctx.clone();

        self.deps
            .repos
            .with_transaction(|mut tx| {
                let recovery_codes = recovery_codes.clone();
                let ctx = ctx.clone();
                async move {
                    let result = async {
                        tx.credentials().delete_recovery_codes_by_user_id(user_id).await?;
                        tx.credentials().insert_recovery_codes(&recovery_codes.0).await?;
                        tx.audit()
                            .insert(&NewAuditEntry {
                                event_type: "user.totp.recovery_codes_regenerated".to_owned(),
                                actor: Actor::User(user_id),
                                target: Some(AuditTarget {
                                    target_type: "user".to_owned(),
                                    target_id: Some(user_id.as_uuid()),
                                }),
                                ip_address: ctx.ip_address.clone(),
                                user_agent: ctx.user_agent.clone(),
                                request_id: ctx.request_id,
                                metadata: Metadata::empty(),
                                created_at: now,
                            })
                            .await?;
                        Ok::<_, AppError>(())
                    }
                    .await;
                    (tx, result)
                }
            })
            .await?;

        Ok(recovery_codes.1)
    }

    async fn generate_recovery_codes(
        &self,
        user_id: UserId,
        now: time::OffsetDateTime,
    ) -> Result<(Vec<RecoveryCode>, Vec<String>), AppError> {
        let count = self.policy().recovery_codes.count as usize;
        let code_length = self.policy().recovery_codes.code_length as usize;
        let mut records = Vec::with_capacity(count);
        let mut raw_codes = Vec::with_capacity(count);

        for _ in 0..count {
            let code = OsRng
                .sample_iter(&Alphanumeric)
                .take(code_length)
                .map(char::from)
                .collect::<String>()
                .to_uppercase();
            let hash = hash_recovery_code(&code);
            records.push(RecoveryCode {
                id: self.deps.ids.recovery_code_id(),
                user_id,
                code_hash: hash,
                state: RecoveryCodeState::Unused,
                created_at: now,
            });
            raw_codes.push(code);
        }

        Ok((records, raw_codes))
    }
}

fn hash_recovery_code(code: &str) -> String {
    let digest = Sha256::digest(code.as_bytes());
    hex::encode(digest)
}

fn build_totp<R, C, H, T, W, K, I, A>(
    app: &AegisApp<R, C, H, T, W, K, I, A>,
    secret: &[u8],
    account_name: &str,
) -> Result<TOTP, AppError>
where
    R: Repos,
    C: Cache,
    H: Hasher,
    T: TokenGenerator,
    W: WebhookDispatcher,
    K: Clock,
    I: IdGenerator,
    A: WebAuthn,
{
    let algorithm = match app.policy().totp.algorithm {
        aegis_core::TotpAlgorithm::Sha1 => Algorithm::SHA1,
        aegis_core::TotpAlgorithm::Sha256 => Algorithm::SHA256,
        aegis_core::TotpAlgorithm::Sha512 => Algorithm::SHA512,
    };

    TOTP::new(
        algorithm,
        app.policy().totp.digits as usize,
        app.policy().totp.skew as u8,
        app.policy().totp.period as u64,
        secret.to_vec(),
        Some(app.policy().totp.issuer.clone()),
        account_name.to_owned(),
    )
    .map_err(|e| AppError::Infrastructure(format!("failed to build totp: {e}")))
}
