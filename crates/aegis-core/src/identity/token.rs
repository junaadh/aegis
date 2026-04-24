use std::fmt;

use time::OffsetDateTime;

use crate::ids::UserId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PendingTokenPurpose {
    EmailVerification,
    PasswordReset,
}

impl PendingTokenPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EmailVerification => "email_verification",
            Self::PasswordReset => "password_reset",
        }
    }
}

impl fmt::Display for PendingTokenPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for PendingTokenPurpose {
    type Err = PendingTokenPurposeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "email_verification" => Ok(Self::EmailVerification),
            "password_reset" => Ok(Self::PasswordReset),
            other => {
                Err(PendingTokenPurposeParseError::Unknown(other.to_owned()))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingTokenPurposeParseError {
    Unknown(String),
}

impl fmt::Display for PendingTokenPurposeParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(s) => write!(f, "unknown pending token purpose: {s}"),
        }
    }
}

impl std::error::Error for PendingTokenPurposeParseError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingToken {
    pub token_hash: [u8; 32],
    pub user_id: UserId,
    pub purpose: PendingTokenPurpose,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
}

impl PendingToken {
    pub fn is_expired_at(&self, now: OffsetDateTime) -> bool {
        self.expires_at <= now
    }
}
