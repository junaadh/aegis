use time::OffsetDateTime;

use crate::ids::{PasswordCredentialId, UserId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordCredential {
    pub id: PasswordCredentialId,
    pub user_id: UserId,
    pub hash: String,
    pub algorithm_version: i32,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
}

impl PasswordCredential {
    pub fn mark_used(&mut self) {
        self.mark_used_at(OffsetDateTime::now_utc());
    }

    pub fn mark_used_at(&mut self, now: OffsetDateTime) {
        self.last_used_at = Some(now);
        self.updated_at = now;
    }

    pub fn update_hash(&mut self, hash: String, algorithm_version: i32) {
        self.update_hash_at(hash, algorithm_version, OffsetDateTime::now_utc());
    }

    pub fn update_hash_at(
        &mut self,
        hash: String,
        algorithm_version: i32,
        now: OffsetDateTime,
    ) {
        self.hash = hash;
        self.algorithm_version = algorithm_version;
        self.updated_at = now;
    }
}
