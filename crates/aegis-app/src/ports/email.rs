use async_trait::async_trait;

use crate::error::AppError;

#[async_trait]
pub trait EmailSender: Send + Sync {
    async fn send_verification(
        &self,
        to: &str,
        token: &str,
    ) -> Result<(), AppError>;
    async fn send_password_reset(
        &self,
        to: &str,
        token: &str,
    ) -> Result<(), AppError>;
}
