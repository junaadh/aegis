use async_trait::async_trait;

use crate::error::AppError;

#[async_trait]
pub trait WebhookDispatcher: Send + Sync {
    async fn dispatch(&self, event: &str, payload: &str) -> Result<(), AppError>;
}
