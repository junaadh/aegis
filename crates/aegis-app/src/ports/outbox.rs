use async_trait::async_trait;

use crate::error::AppError;

#[async_trait]
pub trait OutboxProcessor: Send + Sync {
    async fn process(
        &self,
        job_type: &str,
        payload: &str,
    ) -> Result<(), AppError>;
}
