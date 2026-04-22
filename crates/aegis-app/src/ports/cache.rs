use async_trait::async_trait;
use time::Duration;

use crate::error::AppError;

#[async_trait]
pub trait Cache: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, AppError>;
    async fn set(&self, key: &str, value: Vec<u8>, ttl: Duration) -> Result<(), AppError>;
    async fn delete(&self, key: &str) -> Result<(), AppError>;
}
