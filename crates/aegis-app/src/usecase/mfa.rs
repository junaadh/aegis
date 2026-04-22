use aegis_core::UserId;

use crate::app::AegisApp;
use crate::dto::{TotpEnrollFinishCommand, TotpEnrollResult, TotpVerifyCommand};
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
    pub async fn enroll_totp_start(
        &self,
        user_id: UserId,
    ) -> Result<TotpEnrollResult, AppError> {
        let _ = user_id;
        todo!()
    }

    pub async fn enroll_totp_finish(
        &self,
        user_id: UserId,
        cmd: TotpEnrollFinishCommand,
    ) -> Result<(), AppError> {
        let _ = (user_id, cmd);
        todo!()
    }

    pub async fn verify_totp(
        &self,
        user_id: UserId,
        cmd: TotpVerifyCommand,
    ) -> Result<(), AppError> {
        let _ = (user_id, cmd);
        todo!()
    }

    pub async fn regenerate_recovery_codes(
        &self,
        user_id: UserId,
    ) -> Result<Vec<String>, AppError> {
        let _ = user_id;
        todo!()
    }
}
