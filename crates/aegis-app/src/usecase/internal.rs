use crate::app::AegisApp;
use crate::convert::core_to_output::user_to_lookup_result;
use crate::dto::{HealthResult, LookupUserByEmailCommand, LookupUserCommand,
    RegisterWebhookCommand, SessionValidateResult, UserLookupResult};
use crate::error::AppError;
use crate::ports::{Cache, Clock, GuestRepo, Hasher, IdGenerator, Repos, RoleRepo, SessionRepo,
    TokenGenerator, UserRepo, WebhookDispatcher};

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
    pub async fn validate_session(
        &self,
        cmd: crate::dto::ValidateSessionCommand,
    ) -> Result<SessionValidateResult, AppError> {
        let Some(session) = self
            .deps
            .repos
            .sessions()
            .get_by_token_hash(&cmd.token_hash)
            .await?
        else {
            return Ok(SessionValidateResult {
                valid: false,
                user_id: None,
                guest_id: None,
                status: None,
                expires_at: None,
            });
        };

        let now = self.deps.clock.now();
        if session.is_expired_at(now) {
            return Ok(SessionValidateResult {
                valid: false,
                user_id: None,
                guest_id: None,
                status: Some("expired".to_owned()),
                expires_at: Some(session.expires_at),
            });
        }

        match session.identity {
            aegis_core::SessionIdentity::User(user_id) => {
                let user = self.deps.repos.users().get_by_id(user_id).await?;
                let Some(user) = user else {
                    return Ok(SessionValidateResult {
                        valid: false,
                        user_id: Some(user_id),
                        guest_id: None,
                        status: Some("missing_user".to_owned()),
                        expires_at: Some(session.expires_at),
                    });
                };

                let status = match user.status {
                    aegis_core::UserStatus::Active => "active",
                    aegis_core::UserStatus::PendingVerification => "pending_verification",
                    aegis_core::UserStatus::Disabled => "disabled",
                    aegis_core::UserStatus::Deleted => "deleted",
                }
                .to_owned();

                Ok(SessionValidateResult {
                    valid: matches!(
                        user.status,
                        aegis_core::UserStatus::Active
                            | aegis_core::UserStatus::PendingVerification
                    ),
                    user_id: Some(user.id),
                    guest_id: None,
                    status: Some(status),
                    expires_at: Some(session.expires_at),
                })
            }
            aegis_core::SessionIdentity::Guest(guest_id) => {
                let guest = self.deps.repos.guests().get_by_id(guest_id).await?;
                let Some(guest) = guest else {
                    return Ok(SessionValidateResult {
                        valid: false,
                        user_id: None,
                        guest_id: Some(guest_id),
                        status: Some("missing_guest".to_owned()),
                        expires_at: Some(session.expires_at),
                    });
                };

                Ok(SessionValidateResult {
                    valid: !guest.is_expired_at(now) && guest.status.is_active(),
                    user_id: None,
                    guest_id: Some(guest.id),
                    status: Some(format!("{:?}", guest.status).to_lowercase()),
                    expires_at: Some(session.expires_at),
                })
            }
        }
    }

    pub async fn lookup_user(
        &self,
        cmd: LookupUserCommand,
    ) -> Result<UserLookupResult, AppError> {
        let user = self
            .deps
            .repos
            .users()
            .get_by_id(aegis_core::UserId::from_uuid(cmd.user_id))
            .await?
            .ok_or(AppError::NotFound("user"))?;

        let roles = self
            .deps
            .repos
            .roles()
            .get_roles_by_user_id(user.id)
            .await?;
        let role_names: Vec<String> = roles.iter().map(|r| r.name.as_str().to_owned()).collect();

        Ok(user_to_lookup_result(&user, Some(role_names)))
    }

    pub async fn lookup_user_by_email(
        &self,
        cmd: LookupUserByEmailCommand,
    ) -> Result<UserLookupResult, AppError> {
        let user = self
            .deps
            .repos
            .users()
            .get_by_email(&cmd.email)
            .await?
            .ok_or(AppError::NotFound("user"))?;

        let roles = self
            .deps
            .repos
            .roles()
            .get_roles_by_user_id(user.id)
            .await?;
        let role_names: Vec<String> = roles.iter().map(|r| r.name.as_str().to_owned()).collect();

        Ok(user_to_lookup_result(&user, Some(role_names)))
    }

    pub async fn register_webhook(
        &self,
        cmd: RegisterWebhookCommand,
    ) -> Result<(), AppError> {
        let _ = cmd;
        todo!()
    }

    pub async fn health(&self) -> Result<HealthResult, AppError> {
        Ok(HealthResult {
            status: "ok".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            database_connected: true,
        })
    }
}
