use std::fmt;

use time::OffsetDateTime;

use crate::ids::{TotpCredentialId, UserId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpCredential {
    pub id: TotpCredentialId,
    pub user_id: UserId,
    pub secret_encrypted: Vec<u8>,
    pub nonce: Vec<u8>,
    pub algorithm: TotpAlgorithm,
    pub digits: i32,
    pub period: i32,
    pub enabled: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl TotpCredential {
    pub fn disable(&mut self) {
        self.disable_at(OffsetDateTime::now_utc());
    }

    pub fn disable_at(&mut self, now: OffsetDateTime) {
        self.enabled = false;
        self.updated_at = now;
    }

    pub fn rotate_secret(&mut self, secret_encrypted: Vec<u8>, nonce: Vec<u8>) {
        self.rotate_secret_at(
            secret_encrypted,
            nonce,
            OffsetDateTime::now_utc(),
        );
    }

    pub fn rotate_secret_at(
        &mut self,
        secret_encrypted: Vec<u8>,
        nonce: Vec<u8>,
        now: OffsetDateTime,
    ) {
        self.secret_encrypted = secret_encrypted;
        self.nonce = nonce;
        self.updated_at = now;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl std::fmt::Display for TotpAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TotpAlgorithmParseError {
    Unknown(String),
}

impl fmt::Display for TotpAlgorithmParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(s) => write!(f, "unknown totp algorithm: {s}"),
        }
    }
}

impl std::error::Error for TotpAlgorithmParseError {}

impl std::str::FromStr for TotpAlgorithm {
    type Err = TotpAlgorithmParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "SHA1" => Ok(Self::Sha1),
            "SHA256" => Ok(Self::Sha256),
            "SHA512" => Ok(Self::Sha512),
            other => Err(TotpAlgorithmParseError::Unknown(other.to_owned())),
        }
    }
}
