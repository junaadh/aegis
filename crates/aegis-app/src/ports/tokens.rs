use async_trait::async_trait;

use crate::error::AppError;

#[async_trait]
pub trait TokenGenerator: Send + Sync {
    async fn generate_opaque(
        &self,
        len: usize,
    ) -> Result<(String, [u8; 32]), AppError>;
    async fn hash_token(&self, token: &str) -> [u8; 32];
}
