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
    pub uptime_seconds: u64,
    pub database: ComponentStatus,
    pub cache: ComponentStatus,
    pub email_enabled: bool,
    pub outbox_pending: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComponentStatus {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub page: u32,
    pub per_page: u32,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminUserListItemResponse {
    pub id: String,
    pub email: String,
    pub display_name: String,
    pub status: String,
    pub email_verified: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminUserCredentialSummaryResponse {
    pub has_password: bool,
    pub passkey_count: u64,
    pub totp_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminUserDetailResponse {
    pub id: String,
    pub email: String,
    pub display_name: String,
    pub status: String,
    pub email_verified_at: Option<String>,
    pub metadata: serde_json::Value,
    pub roles: Vec<String>,
    pub credentials: AdminUserCredentialSummaryResponse,
    pub session_count: u64,
    pub last_seen_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OverviewResponse {
    pub total_users: u64,
    pub active_users: u64,
    pub total_guests: u64,
    pub active_guests: u64,
    pub active_sessions: u64,
    pub email_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminGuestListItemResponse {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub converted_to: Option<String>,
    pub expires_at: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminGuestDetailResponse {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub converted_to: Option<String>,
    pub metadata: serde_json::Value,
    pub expires_at: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminSessionListItemResponse {
    pub id: String,
    pub identity_type: String,
    pub identity_id: String,
    pub expires_at: String,
    pub last_seen_at: String,
    pub mfa_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminSessionDetailResponse {
    pub id: String,
    pub identity_type: String,
    pub identity_id: String,
    pub expires_at: String,
    pub last_seen_at: String,
    pub mfa_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    pub metadata: serde_json::Value,
}
