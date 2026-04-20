use time::OffsetDateTime;

use crate::ids::{PasskeyCredentialId, UserId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyCredential {
    pub id: PasskeyCredentialId,
    pub user_id: UserId,
    pub credential_id: String,
    pub public_key: Vec<u8>,
    pub attestation_object: Option<Vec<u8>>,
    pub authenticator_data: Vec<u8>,
    pub sign_count: i64,
    pub transports: Vec<String>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub created_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
}

impl PasskeyCredential {
    pub fn mark_used(&mut self, new_sign_count: i64) {
        self.mark_used_at(new_sign_count, OffsetDateTime::now_utc());
    }

    pub fn mark_used_at(&mut self, new_sign_count: i64, now: OffsetDateTime) {
        self.sign_count = new_sign_count;
        self.last_used_at = Some(now);
    }

    pub fn update_backup_state(&mut self, backup_state: bool) {
        self.backup_state = backup_state;
    }
}
