use async_trait::async_trait;

use crate::error::AppError;

pub struct PasswordHash {
    pub hash: String,
    pub algorithm_version: u32,
}

pub enum PasswordVerifyResult {
    Valid,
    Invalid,
    ValidButRehashNeeded { current_version: u32 },
}

#[async_trait]
pub trait Hasher: Send + Sync {
    fn current_algorithm_version(&self) -> u32;

    async fn hash_password(&self, password: &str) -> Result<PasswordHash, AppError>;

    async fn verify_password(
        &self,
        password: &str,
        hash: &str,
        stored_version: u32,
    ) -> Result<PasswordVerifyResult, AppError>;
}
