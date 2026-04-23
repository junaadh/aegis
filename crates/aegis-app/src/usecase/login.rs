use aegis_core::{Actor, AuditTarget, Metadata, NewAuditEntry, SessionIdentity};

use crate::app::AegisApp;
use crate::dto::{LoginCommand, LoginOutcome, RequestContext};
use crate::error::AppError;
use crate::ports::{AuditRepo, Cache, Clock, CredentialRepo, Hasher, IdGenerator,
    PasswordVerifyResult, Repos, SessionRepo, TokenGenerator, TransactionRepos, UserRepo,
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
    pub async fn login_with_password(
        &self,
        cmd: LoginCommand,
        ctx: &RequestContext,
    ) -> Result<LoginOutcome, AppError> {
        let email = cmd.parse_email()?;
        let email_str = email.as_str();

        let user = self
            .deps
            .repos
            .users()
            .get_by_email(email_str)
            .await?
            .ok_or(AppError::InvalidCredentials)?;

        match user.status {
            aegis_core::UserStatus::Deleted | aegis_core::UserStatus::Disabled => {
                return Err(AppError::Unauthorized)
            }
            aegis_core::UserStatus::PendingVerification => {
                if !self.policy().auth.allow_unverified_login {
                    return Err(AppError::EmailNotVerified);
                }
            }
            aegis_core::UserStatus::Active => {}
        }

        let password_cred = self
            .deps
            .repos
            .credentials()
            .get_password_by_user_id(user.id)
            .await?
            .ok_or(AppError::InvalidCredentials)?;

        let verify_result = self
            .deps
            .hasher
            .verify_password(
                &cmd.password,
                &password_cred.hash,
                password_cred.algorithm_version as u32,
            )
            .await?;

        match verify_result {
            PasswordVerifyResult::Invalid => return Err(AppError::InvalidCredentials),
            PasswordVerifyResult::Valid | PasswordVerifyResult::ValidButRehashNeeded { .. } => {}
        }

        let rehash = match &verify_result {
            PasswordVerifyResult::ValidButRehashNeeded { .. } => {
                let hashed = self.deps.hasher.hash_password(&cmd.password).await?;
                Some((hashed.hash, hashed.algorithm_version))
            }
            _ => None,
        };

        let totp = self
            .deps
            .repos
            .credentials()
            .get_totp_by_user_id(user.id)
            .await?;

        let mfa_verified = totp.as_ref().is_none_or(|t| !t.enabled);

        let now = self.deps.clock.now();
        let issued = self
            .issue_session(SessionIdentity::User(user.id), mfa_verified)
            .await?;

        let user_id = user.id;
        let session_id = issued.session.id;
        let session = issued.session.clone();
        let ctx = ctx.clone();

        let outcome = self.assemble_login_outcome(user, issued);

        self.deps
            .repos
            .with_transaction(|mut tx| {
                let session = session.clone();
                let password_cred = password_cred.clone();
                let rehash = rehash.clone();
                let ctx = ctx.clone();

                async move {
                    let result = async {
                        tx.sessions().insert(&session).await?;

                        if let Some((new_hash, new_version)) = rehash {
                            let mut cred = password_cred;
                            cred.update_hash_at(new_hash, new_version as i32, now);
                            tx.credentials().update_password(&cred).await?;
                        }

                        let audit = NewAuditEntry {
                            event_type: "user.login".to_owned(),
                            actor: Actor::User(user_id),
                            target: Some(AuditTarget {
                                target_type: "session".to_owned(),
                                target_id: Some(session_id.as_uuid()),
                            }),
                            ip_address: ctx.ip_address.clone(),
                            user_agent: ctx.user_agent.clone(),
                            request_id: ctx.request_id,
                            metadata: Metadata::empty(),
                            created_at: now,
                        };
                        tx.audit().insert(&audit).await?;

                        if !mfa_verified {
                            let mfa_audit = NewAuditEntry {
                                event_type: "user.login.mfa_required".to_owned(),
                                actor: Actor::User(user_id),
                                target: Some(AuditTarget {
                                    target_type: "session".to_owned(),
                                    target_id: Some(session_id.as_uuid()),
                                }),
                                ip_address: ctx.ip_address.clone(),
                                user_agent: ctx.user_agent.clone(),
                                request_id: ctx.request_id,
                                metadata: Metadata::empty(),
                                created_at: now,
                            };
                            tx.audit().insert(&mfa_audit).await?;
                        }

                        Ok::<_, AppError>(())
                    }
                    .await;

                    (tx, result)
                }
            })
            .await?;

        Ok(outcome)
    }
}
