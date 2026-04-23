use aegis_core::{
    Actor, AuditTarget, Metadata, NewAuditEntry, PendingTokenPurpose, UserId,
};

use crate::app::AegisApp;
use crate::dto::{ChangePasswordCommand, ForgotPasswordCommand, ResetPasswordCommand,
    RequestContext};
use crate::error::AppError;
use crate::jobs::JobPayload;
use crate::ports::{AuditRepo, Cache, Clock, CredentialRepo, Hasher, IdGenerator, OutboxRepo,
    PendingTokenRepo, Repos, SessionRepo, TokenGenerator, TransactionRepos, UserRepo,
    WebAuthn, WebhookDispatcher};

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
    pub async fn forgot_password(&self, cmd: ForgotPasswordCommand) -> Result<(), AppError> {
        let user = self.deps.repos.users().get_by_email(&cmd.email).await?;

        let user = match user {
            Some(u) if u.status.is_active() || u.status.is_pending_verification() => u,
            _ => return Ok(()),
        };

        let now = self.deps.clock.now();
        let (raw_token, token_hash) = self
            .deps
            .tokens
            .generate_opaque(self.policy().auth.bearer_token_length)
            .await?;

        let expires_at = now + self.policy().email.password_reset_token_ttl;

        let pending = aegis_core::PendingToken {
            token_hash,
            user_id: user.id,
            purpose: PendingTokenPurpose::PasswordReset,
            expires_at,
            created_at: now,
        };

        let user_id = user.id;
        let email = user.email.as_str().to_owned();

        self.deps
            .repos
            .with_transaction(|mut tx| {
                async move {
                    let result = async {
                        tx.tokens().insert(&pending).await?;

                        let job = JobPayload::SendPasswordResetEmail {
                            user_id: user_id.as_uuid(),
                            email,
                            token: raw_token,
                        };
                        tx.outbox().enqueue(&job).await?;

                        let audit = NewAuditEntry {
                            event_type: "user.forgot_password".to_owned(),
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
                }
            })
            .await?;

        Ok(())
    }

    pub async fn reset_password(&self, cmd: ResetPasswordCommand) -> Result<(), AppError> {
        let token_hash = self.deps.tokens.hash_token(&cmd.token).await;

        let pending = self
            .deps
            .repos
            .tokens()
            .get_by_hash(&token_hash, PendingTokenPurpose::PasswordReset)
            .await?
            .ok_or(AppError::TokenInvalid)?;

        let now = self.deps.clock.now();

        if pending.is_expired_at(now) {
            return Err(AppError::TokenInvalid);
        }

        let user = self
            .deps
            .repos
            .users()
            .get_by_id(pending.user_id)
            .await?
            .ok_or(AppError::NotFound("user"))?;

        self.policy()
            .auth
            .password_policy
            .validate(&cmd.new_password, Some(user.email.as_str()))
            .map_err(|violations| {
                AppError::PasswordTooWeak(
                    violations
                        .iter()
                        .map(|v| v.to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                )
            })?;

        let hashed = self.deps.hasher.hash_password(&cmd.new_password).await?;

        let user_id = user.id;
        let revoke_sessions = self.policy().auth.revoke_all_sessions_on_password_reset;

        self.deps
            .repos
            .with_transaction(|mut tx| {
                async move {
                    let result = async {
                        tx.tokens().delete_by_hash(&token_hash).await?;

                        if let Some(mut cred) =
                            tx.credentials().get_password_by_user_id(user_id).await?
                        {
                            cred.update_hash_at(
                                hashed.hash,
                                hashed.algorithm_version as i32,
                                now,
                            );
                            tx.credentials().update_password(&cred).await?;
                        }

                        if revoke_sessions {
                            tx.sessions().delete_by_user_id(user_id).await?;
                        }

                        let audit = NewAuditEntry {
                            event_type: "user.reset_password".to_owned(),
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
                }
            })
            .await
    }

    pub async fn change_password(
        &self,
        user_id: UserId,
        cmd: ChangePasswordCommand,
        ctx: &RequestContext,
    ) -> Result<(), AppError> {
        let user = self
            .deps
            .repos
            .users()
            .get_by_id(user_id)
            .await?
            .ok_or(AppError::NotFound("user"))?;

        let cred = self
            .deps
            .repos
            .credentials()
            .get_password_by_user_id(user_id)
            .await?
            .ok_or(AppError::InvalidCredentials)?;

        let verify = self
            .deps
            .hasher
            .verify_password(
                &cmd.current_password,
                &cred.hash,
                cred.algorithm_version as u32,
            )
            .await?;

        match verify {
            crate::ports::PasswordVerifyResult::Invalid => {
                return Err(AppError::InvalidCredentials);
            }
            crate::ports::PasswordVerifyResult::Valid
            | crate::ports::PasswordVerifyResult::ValidButRehashNeeded { .. } => {}
        }

        self.policy()
            .auth
            .password_policy
            .validate(&cmd.new_password, Some(user.email.as_str()))
            .map_err(|violations| {
                AppError::PasswordTooWeak(
                    violations
                        .iter()
                        .map(|v| v.to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                )
            })?;

        let hashed = self.deps.hasher.hash_password(&cmd.new_password).await?;
        let now = self.deps.clock.now();
        let revoke_sessions = self.policy().auth.revoke_all_sessions_on_password_reset;
        let ctx = ctx.clone();

        self.deps
            .repos
            .with_transaction(|mut tx| {
                let mut cred = cred.clone();
                let ctx = ctx.clone();

                async move {
                    let result = async {
                        cred.update_hash_at(
                            hashed.hash,
                            hashed.algorithm_version as i32,
                            now,
                        );
                        tx.credentials().update_password(&cred).await?;

                        if revoke_sessions {
                            tx.sessions().delete_by_user_id(user_id).await?;
                        }

                        let audit = NewAuditEntry {
                            event_type: "user.change_password".to_owned(),
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
                        };
                        tx.audit().insert(&audit).await?;

                        Ok::<_, AppError>(())
                    }
                    .await;

                    (tx, result)
                }
            })
            .await
    }
}
