use time::OffsetDateTime;

use crate::ids::{RecoveryCodeId, UserId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryCodeState {
    Unused,
    Used { at: OffsetDateTime },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryCode {
    pub id: RecoveryCodeId,
    pub user_id: UserId,
    pub code_hash: String,
    pub state: RecoveryCodeState,
    pub created_at: OffsetDateTime,
}

impl RecoveryCode {
    pub const fn is_used(&self) -> bool {
        matches!(self.state, RecoveryCodeState::Used { .. })
    }

    pub fn redeem(&mut self) -> Result<(), RecoveryCodeError> {
        self.redeem_at(OffsetDateTime::now_utc())
    }

    pub fn redeem_at(&mut self, now: OffsetDateTime) -> Result<(), RecoveryCodeError> {
        if self.is_used() {
            return Err(RecoveryCodeError::AlreadyUsed);
        }

        self.state = RecoveryCodeState::Used { at: now };
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryCodeError {
    AlreadyUsed,
}

impl std::fmt::Display for RecoveryCodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::AlreadyUsed => "recovery code has already been used",
        })
    }
}

impl std::error::Error for RecoveryCodeError {}
