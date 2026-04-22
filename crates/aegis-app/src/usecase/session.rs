use aegis_core::UserId;

use crate::app::AegisApp;
use crate::dto::SessionRevokeCommand;
use crate::error::AppError;
use crate::ports::{Cache, Clock, Hasher, IdGenerator, Repos, TokenGenerator, WebhookDispatcher};

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
    pub async fn revoke_session(
        &self,
        user_id: UserId,
        cmd: SessionRevokeCommand,
    ) -> Result<(), AppError> {
        let _ = (user_id, cmd);
        todo!()
    }

    pub async fn revoke_all_sessions(&self, user_id: UserId) -> Result<(), AppError> {
        let _ = user_id;
        todo!()
    }
}
