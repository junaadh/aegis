use aegis_core::{
    Actor, AuditTarget, Metadata, NewAuditEntry, PasswordCredential, SessionIdentity, User,
};

use crate::app::AegisApp;
use crate::dto::{AuthResult, RequestContext, SignupCommand};
use crate::error::AppError;
use crate::jobs::JobPayload;
use crate::ports::{AuditRepo, CredentialRepo, OutboxRepo, PendingTokenRepo, Repos, SessionRepo,
    TransactionRepos, UserRepo, WebhookDispatcher, Cache, Clock, Hasher, IdGenerator,
    TokenGenerator};

impl<R, C, H, T, W, K, I> AegisApp<R, C, H, T, W, K, I>
where
    R: Repos,
    C: Cache,
    H: Hasher,
    T: TokenGenerator,
    W: WebhookDispatcher,
    K: Clock,
    I: IdGenerator,
{
    pub async fn signup(
        &self,
        cmd: SignupCommand,
        ctx: &RequestContext,
    ) -> Result<AuthResult, AppError> {
        let password = cmd.password.clone();
        let (email, display_name) = cmd.into_parts()?;
        let email_str = email.as_str().to_owned();

        self.policy()
            .auth
            .password_policy
            .validate(&password, Some(email_str.as_str()))
            .map_err(|violations| {
                AppError::PasswordTooWeak(
                    violations
                        .iter()
                        .map(|v| v.to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                )
            })?;

        if self.deps.repos.users().email_exists(&email_str).await? {
            return Err(AppError::EmailAlreadyExists);
        }

        let now = self.deps.clock.now();
        let user_id = self.deps.ids.user_id();
        let cred_id = self.deps.ids.password_cred_id();

        let user = User::builder(user_id, email, display_name)
            .status(if self.policy().email.enabled {
                aegis_core::UserStatus::PendingVerification
            } else {
                aegis_core::UserStatus::Active
            })
            .created_at(now)
            .updated_at(now)
            .build()
            .map_err(|e| AppError::Validation(e.to_string()))?;

        let hashed = self.deps.hasher.hash_password(&password).await?;
        let credential = PasswordCredential {
            id: cred_id,
            user_id,
            hash: hashed.hash,
            algorithm_version: hashed.algorithm_version as i32,
            created_at: now,
            updated_at: now,
            last_used_at: None,
        };

        let issued = self
            .issue_session(SessionIdentity::User(user_id), false)
            .await?;

        let pending_token_data = if self.policy().email.enabled {
            let verification_token = self
                .deps
                .tokens
                .generate_opaque(self.policy().auth.bearer_token_length)
                .await?;
            let verification_expires = now + self.policy().email.verification_token_ttl;
            let token_hash = self.deps.tokens.hash_token(&verification_token.0).await;

            let pending_token = aegis_core::PendingToken {
                token_hash,
                user_id,
                purpose: aegis_core::PendingTokenPurpose::EmailVerification,
                expires_at: verification_expires,
                created_at: now,
            };

            Some((pending_token, verification_token.0, email_str.clone()))
        } else {
            None
        };

        let ctx = ctx.clone();
        let result = self
            .deps
            .repos
            .with_transaction(|mut tx| {
                let user = user.clone();
                let credential = credential.clone();
                let issued_session = issued.session.clone();
                let pending_token_data = pending_token_data.clone();
                let ctx = ctx.clone();

                async move {
                    let result = async {
                        tx.users().insert(&user).await?;
                        tx.credentials().insert_password(&credential).await?;
                        tx.sessions().insert(&issued_session).await?;

                        if let Some((pending_token, raw_token, email)) = pending_token_data {
                            tx.tokens().insert(&pending_token).await?;
                            let job = JobPayload::SendVerificationEmail {
                                user_id: user_id.as_uuid(),
                                email,
                                token: raw_token,
                            };
                            tx.outbox().enqueue(&job).await?;
                        }

                        let audit = NewAuditEntry {
                            event_type: "user.signup".to_owned(),
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
            .await;

        match result {
            Ok(()) => Ok(self.assemble_auth_result(user, issued)),
            Err(AppError::Infrastructure(msg))
                if msg.contains("duplicate key") || msg.contains("unique constraint") =>
            {
                Err(AppError::EmailAlreadyExists)
            }
            Err(e) => Err(e),
        }
    }
}
