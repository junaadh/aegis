use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversionError {
    InvalidTokenHashLength { expected: usize, actual: usize },
    InvalidStatus(String),
    SessionMissingIdentity,
    InvalidMetadata(String),
    InvalidGuestStatus(String),
    InvalidTotpAlgorithm(String),
    InvalidActorType(String),
}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTokenHashLength { expected, actual } => {
                write!(f, "invalid token hash length: expected {expected}, got {actual}")
            }
            Self::InvalidStatus(s) => write!(f, "invalid user status: {s}"),
            Self::SessionMissingIdentity => {
                f.write_str("session has neither user_id nor guest_id")
            }
            Self::InvalidMetadata(s) => write!(f, "invalid metadata json: {s}"),
            Self::InvalidGuestStatus(s) => write!(f, "invalid guest status: {s}"),
            Self::InvalidTotpAlgorithm(s) => write!(f, "invalid totp algorithm: {s}"),
            Self::InvalidActorType(s) => write!(f, "invalid actor type: {s}"),
        }
    }
}

impl std::error::Error for ConversionError {}

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("row conversion failed: {0}")]
    Conversion(#[from] ConversionError),
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),
}
