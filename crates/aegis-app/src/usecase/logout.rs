use aegis_core::{Actor, AuditTarget, Metadata, NewAuditEntry, SessionIdentity};

use crate::app::AegisApp;
use crate::dto::{LogoutCommand, RequestContext};
use crate::error::AppError;
use crate::ports::{AuditRepo, Cache, Clock, Hasher, IdGenerator, Repos, SessionRepo,
    TokenGenerator, TransactionRepos, WebhookDispatcher};

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
    pub async fn logout(
        &self,
        cmd: LogoutCommand,
        ctx: &RequestContext,
    ) -> Result<(), AppError> {
        let session = self
            .deps
            .repos
            .sessions()
            .get_by_token_hash(&cmd.session_token_hash)
            .await?;

        let session = match session {
            Some(s) => s,
            None => return Ok(()),
        };

        let now = self.deps.clock.now();
        let actor = match session.identity {
            SessionIdentity::User(id) => Actor::User(id),
            SessionIdentity::Guest(id) => Actor::Guest(id),
        };

        let session_id = session.id;
        let ctx = ctx.clone();

        self.deps
            .repos
            .with_transaction(|mut tx| {
                let ctx = ctx.clone();
                async move {
                    let result = async {
                        tx.sessions().delete_by_id(session_id).await?;

                        let audit = NewAuditEntry {
                            event_type: "session.logout".to_owned(),
                            actor,
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

                        Ok::<_, AppError>(())
                    }
                    .await;

                    (tx, result)
                }
            })
            .await
    }
}
