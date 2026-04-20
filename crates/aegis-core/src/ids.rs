use std::marker::PhantomData;

use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Id<T>(Uuid, PhantomData<T>);

impl<T> Id<T> {
    pub fn new() -> Self {
        Self(Uuid::now_v7(), PhantomData)
    }

    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid, PhantomData)
    }

    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl<T> Default for Id<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> std::fmt::Display for Id<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

mod markers {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum User {}
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum Guest {}
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum Session {}
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum Role {}
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum PasswordCredential {}
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum PasskeyCredential {}
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum TotpCredential {}
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum RecoveryCode {}
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum Webhook {}
}

pub type UserId = Id<markers::User>;
pub type GuestId = Id<markers::Guest>;
pub type SessionId = Id<markers::Session>;
pub type RoleId = Id<markers::Role>;
pub type PasswordCredentialId = Id<markers::PasswordCredential>;
pub type PasskeyCredentialId = Id<markers::PasskeyCredential>;
pub type TotpCredentialId = Id<markers::TotpCredential>;
pub type RecoveryCodeId = Id<markers::RecoveryCode>;
pub type WebhookId = Id<markers::Webhook>;
