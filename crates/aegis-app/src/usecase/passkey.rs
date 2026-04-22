use crate::app::AegisApp;
use crate::dto::AuthResult;
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
    pub async fn passkey_register_start(&self) -> Result<(), AppError> {
        todo!()
    }

    pub async fn passkey_register_finish(&self) -> Result<(), AppError> {
        todo!()
    }

    pub async fn passkey_login_start(&self) -> Result<(), AppError> {
        todo!()
    }

    pub async fn passkey_login_finish(&self) -> Result<AuthResult, AppError> {
        todo!()
    }
}
