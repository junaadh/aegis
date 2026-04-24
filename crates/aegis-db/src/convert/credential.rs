use aegis_core::{
    PasskeyCredential, PasskeyCredentialId, PasswordCredential,
    PasswordCredentialId, RecoveryCode, RecoveryCodeId, RecoveryCodeState,
    TotpAlgorithm, TotpCredential, TotpCredentialId, UserId,
};

use crate::error::ConversionError;
use crate::row::{
    PasskeyCredentialRow, PasswordCredentialRow, RecoveryCodeRow,
    TotpCredentialRow,
};

impl From<PasswordCredentialRow> for PasswordCredential {
    fn from(row: PasswordCredentialRow) -> Self {
        Self {
            id: PasswordCredentialId::from_uuid(row.id),
            user_id: UserId::from_uuid(row.user_id),
            hash: row.hash,
            algorithm_version: row.algorithm_version,
            created_at: row.created_at,
            updated_at: row.updated_at,
            last_used_at: row.last_used_at,
        }
    }
}

impl From<PasskeyCredentialRow> for PasskeyCredential {
    fn from(row: PasskeyCredentialRow) -> Self {
        Self {
            id: PasskeyCredentialId::from_uuid(row.id),
            user_id: UserId::from_uuid(row.user_id),
            credential_id: row.credential_id,
            public_key: row.public_key,
            attestation_object: row.attestation_object,
            authenticator_data: row.authenticator_data,
            sign_count: row.sign_count,
            transports: row.transports.unwrap_or_default(),
            backup_eligible: row.backup_eligible,
            backup_state: row.backup_state,
            created_at: row.created_at,
            last_used_at: row.last_used_at,
        }
    }
}

impl TryFrom<TotpCredentialRow> for TotpCredential {
    type Error = ConversionError;

    fn try_from(row: TotpCredentialRow) -> Result<Self, Self::Error> {
        let algorithm: TotpAlgorithm = row.algorithm.parse().map_err(|_| {
            ConversionError::InvalidTotpAlgorithm(row.algorithm.clone())
        })?;

        Ok(Self {
            id: TotpCredentialId::from_uuid(row.id),
            user_id: UserId::from_uuid(row.user_id),
            secret_encrypted: row.secret_encrypted,
            nonce: row.nonce,
            algorithm,
            digits: row.digits,
            period: row.period,
            enabled: row.enabled,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

impl From<RecoveryCodeRow> for RecoveryCode {
    fn from(row: RecoveryCodeRow) -> Self {
        Self {
            id: RecoveryCodeId::from_uuid(row.id),
            user_id: UserId::from_uuid(row.user_id),
            code_hash: row.code_hash,
            state: match row.used_at {
                Some(at) => RecoveryCodeState::Used { at },
                None => RecoveryCodeState::Unused,
            },
            created_at: row.created_at,
        }
    }
}
