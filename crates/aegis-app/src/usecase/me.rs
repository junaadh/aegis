use aegis_core::{
    Actor, AuditTarget, GuestId, Metadata, NewAuditEntry, UserId,
};

use crate::app::AegisApp;
use crate::dto::{IdentityResult, RequestContext, UpdateProfileCommand};
use crate::error::AppError;
use crate::ports::{
    AuditRepo, Cache, Clock, CredentialRepo, GuestRepo, Hasher, IdGenerator,
    Repos, RoleRepo, TokenGenerator, TransactionRepos, UserRepo, WebAuthn,
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
    pub async fn get_current_identity(
        &self,
        user_id: UserId,
    ) -> Result<IdentityResult, AppError> {
        let user = self
            .deps
            .repos
            .users()
            .get_by_id(user_id)
            .await?
            .ok_or(AppError::NotFound("user"))?;

        let roles = self
            .deps
            .repos
            .roles()
            .get_roles_by_user_id(user_id)
            .await?;
        let credentials = self
            .deps
            .repos
            .credentials()
            .list_by_user_id(user_id)
            .await?;

        Ok(IdentityResult {
            user: Some(user),
            guest: None,
            roles,
            credentials,
        })
    }

    pub async fn update_profile(
        &self,
        user_id: UserId,
        cmd: UpdateProfileCommand,
        ctx: &RequestContext,
    ) -> Result<IdentityResult, AppError> {
        let display_name = cmd.parse_display_name()?;

        let user = self
            .deps
            .repos
            .users()
            .get_by_id(user_id)
            .await?
            .ok_or(AppError::NotFound("user"))?;

        let Some(name) = display_name else {
            return self.get_current_identity(user_id).await;
        };

        let now = self.deps.clock.now();
        let mut updated_user = user.clone();
        updated_user.change_display_name_at(name, now);

        let ctx = ctx.clone();

        self.deps
            .repos
            .with_transaction(|mut tx| {
                let updated_user = updated_user.clone();
                let ctx = ctx.clone();

                async move {
                    let result = async {
                        tx.users().update(&updated_user).await?;

                        let audit = NewAuditEntry {
                            event_type: "user.update_profile".to_owned(),
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
            .await?;

        let roles = self
            .deps
            .repos
            .roles()
            .get_roles_by_user_id(user_id)
            .await?;
        let credentials = self
            .deps
            .repos
            .credentials()
            .list_by_user_id(user_id)
            .await?;

        Ok(IdentityResult {
            user: Some(updated_user),
            guest: None,
            roles,
            credentials,
        })
    }

    pub async fn get_guest_identity(
        &self,
        guest_id: GuestId,
    ) -> Result<IdentityResult, AppError> {
        let guest = self
            .deps
            .repos
            .guests()
            .get_by_id(guest_id)
            .await?
            .ok_or(AppError::NotFound("guest"))?;

        Ok(IdentityResult {
            user: None,
            guest: Some(guest),
            roles: vec![],
            credentials: vec![],
        })
    }
}
