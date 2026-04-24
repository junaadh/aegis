use aegis_core::{PendingToken, PendingTokenPurpose, UserId};

use crate::error::ConversionError;
use crate::row::{EmailVerificationTokenRow, PasswordResetTokenRow};

impl TryFrom<EmailVerificationTokenRow> for PendingToken {
    type Error = ConversionError;

    fn try_from(row: EmailVerificationTokenRow) -> Result<Self, Self::Error> {
        let token_hash: [u8; 32] =
            row.token_hash.try_into().map_err(|v: Vec<u8>| {
                ConversionError::InvalidTokenHashLength {
                    expected: 32,
                    actual: v.len(),
                }
            })?;

        Ok(Self {
            token_hash,
            user_id: UserId::from_uuid(row.user_id),
            purpose: PendingTokenPurpose::EmailVerification,
            expires_at: row.expires_at,
            created_at: row.created_at,
        })
    }
}

impl TryFrom<PasswordResetTokenRow> for PendingToken {
    type Error = ConversionError;

    fn try_from(row: PasswordResetTokenRow) -> Result<Self, Self::Error> {
        let token_hash: [u8; 32] =
            row.token_hash.try_into().map_err(|v: Vec<u8>| {
                ConversionError::InvalidTokenHashLength {
                    expected: 32,
                    actual: v.len(),
                }
            })?;

        Ok(Self {
            token_hash,
            user_id: UserId::from_uuid(row.user_id),
            purpose: PendingTokenPurpose::PasswordReset,
            expires_at: row.expires_at,
            created_at: row.created_at,
        })
    }
}
