use crate::{
    identity::{Metadata, UserStatus},
    ids::{Id, UserId},
    traits::Anonymize,
};
use std::{fmt, str::FromStr};
use time::OffsetDateTime;

/// Registered identity owned by Aegis.
///
/// `User` is the authoritative core identity record.
/// It intentionally contains only identity-layer data and avoids
/// business-domain profile data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: UserId,
    pub email: EmailAddress,
    pub display_name: DisplayName,
    pub status: UserStatus,
    pub email_verified_at: Option<OffsetDateTime>,
    pub metadata: Metadata,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
    pub anonymize_at: Option<OffsetDateTime>,
    pub anonymize_after: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserBuilder {
    id: UserId,
    email: EmailAddress,
    display_name: DisplayName,
    status: UserStatus,
    email_verified_at: Option<OffsetDateTime>,
    metadata: Metadata,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    deleted_at: Option<OffsetDateTime>,
    anonymize_at: Option<OffsetDateTime>,
    anonymize_after: Option<OffsetDateTime>,
}

impl UserBuilder {
    pub fn new(id: UserId, email: EmailAddress, display_name: DisplayName) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            id,
            email,
            display_name,
            status: UserStatus::PendingVerification,
            email_verified_at: None,
            metadata: Metadata::empty(),
            created_at: now,
            updated_at: now,
            deleted_at: None,
            anonymize_at: None,
            anonymize_after: None,
        }
    }

    pub fn status(mut self, status: UserStatus) -> Self {
        self.status = status;
        self
    }

    pub fn email_verified_at(mut self, ts: OffsetDateTime) -> Self {
        self.email_verified_at = Some(ts);
        self
    }

    pub fn metadata(mut self, metadata: Metadata) -> Self {
        self.metadata = metadata;
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

    pub fn deleted_at(mut self, ts: OffsetDateTime) -> Self {
        self.deleted_at = Some(ts);
        self
    }

    pub fn anonymize_at(mut self, ts: OffsetDateTime) -> Self {
        self.anonymize_at = Some(ts);
        self
    }

    pub fn anonymize_after(mut self, ts: OffsetDateTime) -> Self {
        self.anonymize_after = Some(ts);
        self
    }

    pub fn build(self) -> Result<User, UserError> {
        if self.status.is_deleted() && self.deleted_at.is_none() {
            return Err(UserError::DeletedUserMissingTimestamp);
        }

        if !self.status.is_deleted() && self.deleted_at.is_some() {
            return Err(UserError::NonDeletedUserHasDeletedTimestamp);
        }

        Ok(User {
            id: self.id,
            email: self.email,
            display_name: self.display_name,
            status: self.status,
            email_verified_at: self.email_verified_at,
            metadata: self.metadata,
            created_at: self.created_at,
            updated_at: self.updated_at,
            deleted_at: self.deleted_at,
            anonymize_at: self.anonymize_at,
            anonymize_after: self.anonymize_after,
        })
    }
}

impl User {
    pub fn builder(
        id: UserId,
        email: EmailAddress,
        display_name: DisplayName,
    ) -> UserBuilder {
        UserBuilder::new(id, email, display_name)
    }

    pub const fn is_active(&self) -> bool {
        self.status.is_active()
    }

    pub const fn is_deleted(&self) -> bool {
        self.status.is_deleted()
    }

    pub const fn is_disabled(&self) -> bool {
        self.status.is_disabled()
    }

    pub const fn is_email_verified(&self) -> bool {
        self.email_verified_at.is_some()
    }

    pub const fn can_authenticate(&self) -> bool {
        self.status.can_authenticate()
    }

    pub fn verify_email(&mut self) {
        self.verify_email_at(OffsetDateTime::now_utc());
    }

    pub fn verify_email_at(&mut self, now: OffsetDateTime) {
        self.email_verified_at = Some(now);

        if self.status.is_pending_verification() {
            self.status = UserStatus::Active;
        }

        self.updated_at = now;
    }

    pub fn change_display_name(&mut self, display_name: DisplayName) {
        self.change_display_name_at(display_name, OffsetDateTime::now_utc());
    }

    pub fn change_display_name_at(
        &mut self,
        display_name: DisplayName,
        now: OffsetDateTime,
    ) {
        self.display_name = display_name;
        self.updated_at = now;
    }

    pub fn change_email(&mut self, email: EmailAddress) {
        self.change_email_at(email, OffsetDateTime::now_utc());
    }

    pub fn change_email_at(
        &mut self,
        email: EmailAddress,
        now: OffsetDateTime,
    ) {
        self.email = email;
        self.email_verified_at = None;

        if self.status.is_active() {
            self.status = UserStatus::PendingVerification;
        }

        self.updated_at = now;
    }

    pub fn disable(&mut self) -> Result<(), UserError> {
        self.disable_at(OffsetDateTime::now_utc())
    }

    pub fn disable_at(&mut self, now: OffsetDateTime) -> Result<(), UserError> {
        if self.is_deleted() {
            return Err(UserError::DeletedUserCannotTransition);
        }

        self.status = UserStatus::Disabled;
        self.updated_at = now;
        Ok(())
    }

    pub fn activate(&mut self) -> Result<(), UserError> {
        self.activate_at(OffsetDateTime::now_utc())
    }

    pub fn activate_at(
        &mut self,
        now: OffsetDateTime,
    ) -> Result<(), UserError> {
        if self.is_deleted() {
            return Err(UserError::DeletedUserCannotTransition);
        }

        self.status = if self.is_email_verified() {
            UserStatus::Active
        } else {
            UserStatus::PendingVerification
        };

        self.updated_at = now;
        Ok(())
    }

    pub fn delete(&mut self) {
        self.delete_at(OffsetDateTime::now_utc())
    }

    pub fn delete_at(&mut self, now: OffsetDateTime) {
        self.status = UserStatus::Deleted;
        self.deleted_at = Some(now);
        self.updated_at = now;
    }
}

impl Anonymize for User {
    type Err = UserError;

    fn deleted_at(&self) -> Option<OffsetDateTime> {
        self.deleted_at
    }

    fn anonymize_after(&self) -> Option<OffsetDateTime> {
        self.anonymize_after
    }

    fn anonymized_at(&self) -> Option<OffsetDateTime> {
        self.anonymize_at
    }

    fn anonymize(&mut self, at: OffsetDateTime) -> Result<(), Self::Err> {
        if !self.is_deleted() {
            return Err(UserError::UserNotDeleted);
        }

        if self.anonymize_at.is_some() {
            return Err(UserError::AlreadyAnonymized);
        }

        self.email.anonymize(self.id)?;
        self.display_name.anonymize()?;
        self.metadata = Metadata::empty();
        self.anonymize_at = Some(at);

        Ok(())
    }
}

/// Canonical email address used for identity and communication
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EmailAddress(String);

impl EmailAddress {
    pub fn parse(input: impl AsRef<str>) -> Result<Self, EmailAddressError> {
        input.as_ref().parse()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    pub fn anonymize<T>(&mut self, id: Id<T>) -> Result<(), EmailAddressError> {
        *self = Self::parse(format!(
            "deleted-{}@anonymized.local",
            &id.to_string()[..12]
        ))?;
        Ok(())
    }
}

impl FromStr for EmailAddress {
    type Err = EmailAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();

        if trimmed.is_empty() {
            return Err(EmailAddressError::Empty);
        }

        if trimmed.len() > 320 {
            return Err(EmailAddressError::TooLong);
        }

        if !trimmed.contains('@') {
            return Err(EmailAddressError::MissingAtSign);
        }

        let normalized = trimmed.to_ascii_lowercase();

        Ok(Self(normalized))
    }
}

impl fmt::Display for EmailAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Human-readable identity display label
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DisplayName(String);

impl DisplayName {
    pub fn parse(input: impl AsRef<str>) -> Result<Self, DisplayNameError> {
        input.as_ref().parse()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    pub fn anonymize(&mut self) -> Result<(), DisplayNameError> {
        *self = Self::parse("[Deleted User]")?;
        Ok(())
    }
}

impl FromStr for DisplayName {
    type Err = DisplayNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();

        if trimmed.is_empty() {
            return Err(DisplayNameError::Empty);
        }

        if trimmed.len() > 100 {
            return Err(DisplayNameError::TooLong);
        }

        Ok(Self(trimmed.to_owned()))
    }
}

impl fmt::Display for DisplayName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmailAddressError {
    Empty,
    TooLong,
    MissingAtSign,
}

impl fmt::Display for EmailAddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "email cannot be empty",
            Self::TooLong => "email is too long",
            Self::MissingAtSign => "email must contain '@'",
        })
    }
}

impl std::error::Error for EmailAddressError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserError {
    DeletedUserMissingTimestamp,
    NonDeletedUserHasDeletedTimestamp,
    DeletedUserCannotTransition,
    UserNotDeleted,
    AlreadyAnonymized,
    AnonymizeEmailFailed(EmailAddressError),
    AnonymizeDisplayNameFailed(DisplayNameError),
}

impl fmt::Display for UserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeletedUserMissingTimestamp => {
                f.write_str("deleted user must have deleted_at set")
            }
            Self::NonDeletedUserHasDeletedTimestamp => {
                f.write_str("non-deleted user must not have deleted_at set")
            }
            Self::DeletedUserCannotTransition => {
                f.write_str("deleted user cannot transition state")
            }
            Self::UserNotDeleted => f.write_str("user must be deleted before anonymization"),
            Self::AlreadyAnonymized => f.write_str("user is already anonymized"),
            Self::AnonymizeEmailFailed(e) => write!(f, "email anonymization failed: {e}"),
            Self::AnonymizeDisplayNameFailed(e) => {
                write!(f, "display name anonymization failed: {e}")
            }
        }
    }
}

impl std::error::Error for UserError {}

impl From<EmailAddressError> for UserError {
    fn from(e: EmailAddressError) -> Self {
        Self::AnonymizeEmailFailed(e)
    }
}

impl From<DisplayNameError> for UserError {
    fn from(e: DisplayNameError) -> Self {
        Self::AnonymizeDisplayNameFailed(e)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisplayNameError {
    Empty,
    TooLong,
}

impl fmt::Display for DisplayNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "display name cannot be empty",
            Self::TooLong => "display name is too long",
        })
    }
}

impl std::error::Error for DisplayNameError {}
