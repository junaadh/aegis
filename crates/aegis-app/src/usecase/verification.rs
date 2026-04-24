use aegis_core::{
    Actor, AuditTarget, Metadata, NewAuditEntry, PendingTokenPurpose,
};

use crate::app::AegisApp;
use crate::dto::{ResendVerificationCommand, VerifyEmailCommand};
use crate::error::AppError;
use crate::jobs::JobPayload;
use crate::ports::{
    AuditRepo, Cache, Clock, Hasher, IdGenerator, OutboxRepo, PendingTokenRepo,
    Repos, TokenGenerator, TransactionRepos, UserRepo, WebAuthn,
    WebhookDispatcher,
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
    pub async fn verify_email(
        &self,
        cmd: VerifyEmailCommand,
    ) -> Result<(), AppError> {
        let token_hash = self.deps.tokens.hash_token(&cmd.token).await;

        let pending = self
            .deps
            .repos
            .tokens()
            .get_by_hash(&token_hash, PendingTokenPurpose::EmailVerification)
            .await?
            .ok_or(AppError::TokenInvalid)?;

        let now = self.deps.clock.now();

        if pending.is_expired_at(now) {
            return Err(AppError::TokenInvalid);
        }

        let mut user = self
            .deps
            .repos
            .users()
            .get_by_id(pending.user_id)
            .await?
            .ok_or(AppError::NotFound("user"))?;

        let already_verified = user.is_email_verified();

        if !already_verified {
            user.verify_email_at(now);
        }

        let user_id = user.id;

        self.deps
            .repos
            .with_transaction(|mut tx| {
                let user = user.clone();
                async move {
                    let result = async {
                        if !already_verified {
                            tx.users().update(&user).await?;
                        }

                        tx.tokens().delete_by_hash(&token_hash).await?;

                        if !already_verified {
                            let audit = NewAuditEntry {
                                event_type: "user.verify_email".to_owned(),
                                actor: Actor::User(user_id),
                                target: Some(AuditTarget {
                                    target_type: "user".to_owned(),
                                    target_id: Some(user_id.as_uuid()),
                                }),
                                ip_address: None,
                                user_agent: None,
                                request_id: None,
                                metadata: Metadata::empty(),
                                created_at: now,
                            };
                            tx.audit().insert(&audit).await?;
                        }

                        Ok::<_, AppError>(())
                    }
                    .await;

                    (tx, result)
                }
            })
            .await
    }

    pub async fn resend_verification(
        &self,
        cmd: ResendVerificationCommand,
    ) -> Result<(), AppError> {
        if !self.policy().email.enabled {
            return Err(AppError::Validation(
                "email verification is not enabled".to_owned(),
            ));
        }

        let user = self
            .deps
            .repos
            .users()
            .get_by_email(&cmd.email)
            .await?
            .ok_or(AppError::NotFound("user"))?;

        if user.is_email_verified() {
            return Ok(());
        }

        if !user.status.is_pending_verification() {
            return Ok(());
        }

        let now = self.deps.clock.now();
        let (raw_token, token_hash) = self
            .deps
            .tokens
            .generate_opaque(self.policy().auth.bearer_token_length)
            .await?;

        let expires_at = now + self.policy().email.verification_token_ttl;

        let pending = aegis_core::PendingToken {
            id: uuid::Uuid::now_v7(),
            token_hash,
            user_id: user.id,
            purpose: PendingTokenPurpose::EmailVerification,
            expires_at,
            created_at: now,
        };

        let user_id = user.id;
        let email = user.email.as_str().to_owned();

        self.deps
            .repos
            .with_transaction(|mut tx| async move {
                let result = async {
                    tx.tokens().insert(&pending).await?;

                    let job = JobPayload::SendVerificationEmail {
                        user_id: user_id.as_uuid(),
                        email,
                        token: raw_token,
                    };
                    tx.outbox().enqueue(&job).await?;

                    let audit = NewAuditEntry {
                        event_type: "user.resend_verification".to_owned(),
                        actor: Actor::User(user_id),
                        target: Some(AuditTarget {
                            target_type: "user".to_owned(),
                            target_id: Some(user_id.as_uuid()),
                        }),
                        ip_address: None,
                        user_agent: None,
                        request_id: None,
                        metadata: Metadata::empty(),
                        created_at: now,
                    };
                    tx.audit().insert(&audit).await?;

                    Ok::<_, AppError>(())
                }
                .await;

                (tx, result)
            })
            .await
    }
}
