use std::fmt;

use crate::{
    ids::{GuestId, UserId},
    identity::user::EmailAddress,
    identity::{GuestStatus, Metadata},
};
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Guest {
    pub id: GuestId,
    pub email: Option<EmailAddress>,
    pub status: GuestStatus,
    pub metadata: Metadata,
    pub converted_to: Option<UserId>,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestBuilder {
    id: GuestId,
    email: Option<EmailAddress>,
    status: GuestStatus,
    metadata: Metadata,
    converted_to: Option<UserId>,
    expires_at: OffsetDateTime,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl GuestBuilder {
    pub fn new(id: GuestId, expires_at: OffsetDateTime) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            id,
            email: None,
            status: GuestStatus::Active,
            metadata: Metadata::empty(),
            converted_to: None,
            expires_at,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn email(mut self, email: EmailAddress) -> Self {
        self.email = Some(email);
        self
    }

    pub fn status(mut self, status: GuestStatus) -> Self {
        self.status = status;
        self
    }

    pub fn metadata(mut self, metadata: Metadata) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn converted_to(mut self, user_id: UserId) -> Self {
        self.converted_to = Some(user_id);
        self
    }

    pub fn created_at(mut self, ts: OffsetDateTime) -> Self {
        self.created_at = ts;
        self
    }

    pub fn updated_at(mut self, ts: OffsetDateTime) -> Self {
        self.updated_at = ts;
        self
    }

    pub fn build(self) -> Result<Guest, GuestError> {
        if self.converted_to.is_some() && !self.status.is_converted() {
            return Err(GuestError::ConvertedUserWithoutStatus);
        }

        if self.converted_to.is_none() && self.status.is_converted() {
            return Err(GuestError::ConvertedStatusWithoutUser);
        }

        Ok(Guest {
            id: self.id,
            email: self.email,
            status: self.status,
            metadata: self.metadata,
            converted_to: self.converted_to,
            expires_at: self.expires_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

impl Guest {
    pub fn builder(id: GuestId, expires_at: OffsetDateTime) -> GuestBuilder {
        GuestBuilder::new(id, expires_at)
    }

    pub fn is_expired_at(&self, now: OffsetDateTime) -> bool {
        self.expires_at <= now
    }

    pub fn associate_email(&mut self, email: EmailAddress) {
        self.associate_email_at(email, OffsetDateTime::now_utc());
    }

    pub fn associate_email_at(&mut self, email: EmailAddress, now: OffsetDateTime) {
        self.email = Some(email);
        self.updated_at = now;
    }

    pub fn convert_to_user(&mut self, user_id: UserId) -> Result<(), GuestError> {
        self.convert_to_user_at(user_id, OffsetDateTime::now_utc())
    }

    pub fn convert_to_user_at(
        &mut self,
        user_id: UserId,
        now: OffsetDateTime,
    ) -> Result<(), GuestError> {
        if !self.status.can_convert() {
            return Err(GuestError::NotConvertible);
        }

        self.status = GuestStatus::Converted;
        self.converted_to = Some(user_id);
        self.updated_at = now;
        Ok(())
    }

    pub fn mark_expired(&mut self) {
        self.mark_expired_at(OffsetDateTime::now_utc());
    }

    pub fn mark_expired_at(&mut self, now: OffsetDateTime) {
        if self.status.is_active() {
            self.status = GuestStatus::Expired;
            self.updated_at = now;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestError {
    ConvertedUserWithoutStatus,
    ConvertedStatusWithoutUser,
    NotConvertible,
}

impl fmt::Display for GuestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ConvertedUserWithoutStatus => {
                "guest has converted_to set but status is not converted"
            }
            Self::ConvertedStatusWithoutUser => {
                "guest has converted status but no converted_to user id"
            }
            Self::NotConvertible => "guest is not in a convertible state",
        })
    }
}

impl std::error::Error for GuestError {}
