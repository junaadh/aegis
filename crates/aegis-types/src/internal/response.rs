use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityLookupResponse {
    pub id: Option<String>,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub status: Option<String>,
    pub email_verified: Option<bool>,
    pub roles: Option<Vec<String>>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub database_connected: bool,
}
