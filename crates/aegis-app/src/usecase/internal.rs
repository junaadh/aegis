use crate::app::AegisApp;
use crate::convert::core_to_output::user_to_lookup_result;
use crate::dto::{HealthResult, LookupUserByEmailCommand, LookupUserCommand,
    RegisterWebhookCommand, SessionValidateResult, UserLookupResult};
use crate::error::AppError;
use crate::ports::{Cache, Clock, Hasher, IdGenerator, Repos, RoleRepo, TokenGenerator,
    UserRepo, WebhookDispatcher};

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
        let _ = cmd;
        todo!()
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
        todo!()
    }
}
