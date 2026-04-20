use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    pub expires_at: String,
    pub mfa_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionValidateResponse {
    pub valid: bool,
    pub user_id: Option<String>,
    pub guest_id: Option<String>,
    pub status: Option<String>,
    pub expires_at: Option<String>,
}
