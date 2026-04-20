use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct PasswordCredentialRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub hash: String,
    pub algorithm_version: i32,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct PasskeyCredentialRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: String,
    pub public_key: Vec<u8>,
    pub attestation_object: Option<Vec<u8>>,
    pub authenticator_data: Vec<u8>,
    pub sign_count: i64,
    pub transports: Option<Vec<String>>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub created_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct TotpCredentialRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub secret_encrypted: Vec<u8>,
    pub nonce: Vec<u8>,
    pub algorithm: String,
    pub digits: i32,
    pub period: i32,
    pub enabled: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct RecoveryCodeRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub code_hash: String,
    pub used_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}
