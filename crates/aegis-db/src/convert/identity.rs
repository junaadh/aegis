use aegis_core::{
    DisplayName, EmailAddress, Guest, GuestId, GuestStatus, Metadata, Session, SessionId,
    SessionIdentity, User, UserId, UserStatus,
};

use crate::error::ConversionError;
use crate::row::{GuestRow, SessionRow, UserRow};

impl TryFrom<UserRow> for User {
    type Error = ConversionError;

    fn try_from(row: UserRow) -> Result<Self, Self::Error> {
        let status: UserStatus = row
            .status
            .parse()
            .map_err(|_| ConversionError::InvalidStatus(row.status.clone()))?;

        let email = EmailAddress::parse(&row.email)
            .map_err(|_| ConversionError::InvalidStatus(format!("invalid email: {}", row.email)))?;

        let display_name = DisplayName::parse(&row.display_name)
            .map_err(|_| ConversionError::InvalidStatus(format!("invalid display_name: {}", row.display_name)))?;

        let metadata = Metadata::new(serde_json::to_string(&row.metadata).unwrap_or_default());

        let mut builder = User::builder(UserId::from_uuid(row.id), email, display_name)
            .status(status)
            .metadata(metadata)
            .created_at(row.created_at)
            .updated_at(row.updated_at);

        if let Some(ts) = row.email_verified_at {
            builder = builder.email_verified_at(ts);
        }

        if let Some(ts) = row.deleted_at {
            builder = builder.deleted_at(ts);
        }

        builder.build().map_err(|_| ConversionError::InvalidStatus("user invariant violated".to_owned()))
    }
}

impl TryFrom<GuestRow> for Guest {
    type Error = ConversionError;

    fn try_from(row: GuestRow) -> Result<Self, Self::Error> {
        let email = row.email.as_deref()
            .map(EmailAddress::parse)
            .transpose()
            .map_err(|_| ConversionError::InvalidStatus("invalid guest email".to_owned()))?;

        let metadata = Metadata::new(serde_json::to_string(&row.metadata).unwrap_or_default());

        let mut builder = Guest::builder(GuestId::from_uuid(row.id), row.expires_at)
            .metadata(metadata)
            .created_at(row.created_at)
            .updated_at(row.updated_at);

        if let Some(email) = email {
            builder = builder.email(email);
        }

        if let Some(uid) = row.converted_to {
            builder = builder.status(GuestStatus::Converted);
            builder = builder.converted_to(UserId::from_uuid(uid));
        }

        builder.build().map_err(|_| ConversionError::InvalidGuestStatus("guest invariant violated".to_owned()))
    }
}

impl TryFrom<SessionRow> for Session {
    type Error = ConversionError;

    fn try_from(row: SessionRow) -> Result<Self, Self::Error> {
        let token_hash: [u8; 32] = row
            .token_hash
            .try_into()
            .map_err(|v: Vec<u8>| ConversionError::InvalidTokenHashLength {
                expected: 32,
                actual: v.len(),
            })?;

        let identity = match (row.user_id, row.guest_id) {
            (Some(uid), None) => SessionIdentity::User(UserId::from_uuid(uid)),
            (None, Some(gid)) => SessionIdentity::Guest(GuestId::from_uuid(gid)),
            _ => return Err(ConversionError::SessionMissingIdentity),
        };

        let metadata = Metadata::new(serde_json::to_string(&row.metadata).unwrap_or_default());

        Ok(Session::builder(SessionId::from_uuid(row.id), token_hash, identity, row.expires_at)
            .last_seen_at(row.last_seen_at)
            .mfa_verified(row.mfa_verified)
            .metadata(metadata)
            .build())
    }
}
