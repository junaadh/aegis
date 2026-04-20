use crate::{
    ids::{GuestId, UserId},
    identity::{GuestStatus, Metadata, UserStatus},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identity {
    User(UserIdentity),
    Guest(GuestIdentity),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserIdentity {
    pub id: UserId,
    pub status: UserStatus,
    pub email_verified: bool,
    pub metadata: Metadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestIdentity {
    pub id: GuestId,
    pub status: GuestStatus,
    pub metadata: Metadata,
}
