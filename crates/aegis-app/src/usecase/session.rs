use aegis_core::{Actor, AuditTarget, Metadata, NewAuditEntry, UserId};

use crate::app::AegisApp;
use crate::dto::{RequestContext, SessionRevokeCommand};
use crate::error::AppError;
use crate::ports::{
    AuditRepo, Cache, Clock, Hasher, IdGenerator, Repos, SessionRepo, TokenGenerator,
    TransactionRepos, WebAuthn, WebhookDispatcher,
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
    pub async fn revoke_session(
        &self,
        user_id: UserId,
        cmd: SessionRevokeCommand,
        ctx: &RequestContext,
    ) -> Result<(), AppError> {
        let session_id = cmd
            .session_id
            .map(aegis_core::SessionId::from_uuid)
            .ok_or_else(|| AppError::Validation("session_id is required".to_owned()))?;

        let session = self
            .deps
            .repos
            .sessions()
            .get_by_id(session_id)
            .await?
            .ok_or(AppError::NotFound("session"))?;

        if session.user_id() != Some(user_id) {
            return Err(AppError::Forbidden);
        }

        let now = self.deps.clock.now();
        let ctx = ctx.clone();
        self.deps
            .repos
            .with_transaction(|mut tx| {
                let ctx = ctx.clone();
                async move {
                    let result = async {
                        tx.sessions().delete_by_id(session_id).await?;
                        tx.audit()
                            .insert(&NewAuditEntry {
                                event_type: "session.revoked".to_owned(),
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

    pub async fn revoke_all_sessions(
        &self,
        user_id: UserId,
        current_session_token_hash: Option<[u8; 32]>,
        ctx: &RequestContext,
    ) -> Result<(), AppError> {
        let current_session = if let Some(hash) = current_session_token_hash {
            self.deps.repos.sessions().get_by_token_hash(&hash).await?
        } else {
            None
        };

        let now = self.deps.clock.now();
        let ctx = ctx.clone();
        self.deps
            .repos
            .with_transaction(|mut tx| {
                let current_session = current_session.clone();
                let ctx = ctx.clone();
                async move {
                    let result = async {
                        tx.sessions().delete_by_user_id(user_id).await?;
                        if let Some(current) = current_session
                            && current.user_id() == Some(user_id)
                        {
                            tx.sessions().insert(&current).await?;
                        }
                        tx.audit()
                            .insert(&NewAuditEntry {
                                event_type: "session.revoke_all".to_owned(),
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
            .await
    }
}
