use std::fmt;

use time::OffsetDateTime;

use crate::{
    identity::Metadata,
    ids::{GuestId, UserId},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Actor {
    User(UserId),
    Guest(GuestId),
    Service(String),
    System,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditTarget {
    pub target_type: String,
    pub target_id: Option<uuid::Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub id: i64,
    pub event_type: String,
    pub actor: Actor,
    pub target: Option<AuditTarget>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<uuid::Uuid>,
    pub metadata: Metadata,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAuditEntry {
    pub event_type: String,
    pub actor: Actor,
    pub target: Option<AuditTarget>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<uuid::Uuid>,
    pub metadata: Metadata,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActorType {
    User,
    Guest,
    Service,
    System,
}

impl ActorType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Guest => "guest",
            Self::Service => "service",
            Self::System => "system",
        }
    }
}

impl fmt::Display for ActorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for ActorType {
    type Err = ActorTypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "user" => Ok(Self::User),
            "guest" => Ok(Self::Guest),
            "service" => Ok(Self::Service),
            "system" => Ok(Self::System),
            other => Err(ActorTypeParseError::Unknown(other.to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActorTypeParseError {
    Unknown(String),
}

impl fmt::Display for ActorTypeParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(s) => write!(f, "unknown actor type: {s}"),
        }
    }
}

impl std::error::Error for ActorTypeParseError {}
