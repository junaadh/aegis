use async_trait::async_trait;

use crate::error::AppError;

#[derive(Debug, Clone)]
pub struct PasskeyRegisterStartResult {
    pub public_key: serde_json::Value,
    pub state: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PasskeyRegisterFinishResult {
    pub credential_id: String,
    pub public_key: Vec<u8>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub transports: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PasskeyLoginStartResult {
    pub public_key: serde_json::Value,
    pub state: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PasskeyLoginFinishResult {
    pub credential_id: String,
    pub sign_count: u32,
}

#[async_trait]
pub trait WebAuthn: Send + Sync {
    async fn start_registration(
        &self,
        user_id: &str,
        user_name: &str,
        display_name: &str,
        exclude_credentials: Vec<String>,
    ) -> Result<PasskeyRegisterStartResult, AppError>;

    async fn finish_registration(
        &self,
        state: &[u8],
        response: &[u8],
    ) -> Result<PasskeyRegisterFinishResult, AppError>;

    async fn start_authentication(
        &self,
        credentials: Vec<(String, Vec<u8>)>,
    ) -> Result<PasskeyLoginStartResult, AppError>;

    async fn finish_authentication(
        &self,
        state: &[u8],
        response: &[u8],
    ) -> Result<PasskeyLoginFinishResult, AppError>;
}
