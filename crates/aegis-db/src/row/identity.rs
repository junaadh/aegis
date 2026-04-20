use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct UserRow {
    pub id: Uuid,
    pub email: String,
    pub email_verified_at: Option<OffsetDateTime>,
    pub display_name: String,
    pub status: String,
    pub metadata: serde_json::Value,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GuestRow {
    pub id: Uuid,
    pub email: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub converted_to: Option<Uuid>,
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct SessionRow {
    pub id: Uuid,
    pub token_hash: Vec<u8>,
    pub user_id: Option<Uuid>,
    pub guest_id: Option<Uuid>,
    pub expires_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
    pub mfa_verified: bool,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub metadata: serde_json::Value,
}
