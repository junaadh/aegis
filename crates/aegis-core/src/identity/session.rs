use crate::{
    identity::Metadata,
    ids::{GuestId, SessionId, UserId},
};
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionIdentity {
    User(UserId),
    Guest(GuestId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub id: SessionId,
    pub token_hash: [u8; 32],
    pub identity: SessionIdentity,
    pub expires_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
    pub mfa_verified: bool,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub metadata: Metadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionBuilder {
    id: SessionId,
    token_hash: [u8; 32],
    identity: SessionIdentity,
    expires_at: OffsetDateTime,
    last_seen_at: OffsetDateTime,
    mfa_verified: bool,
    user_agent: Option<String>,
    ip_address: Option<String>,
    metadata: Metadata,
}

impl SessionBuilder {
    pub fn new(
        id: SessionId,
        token_hash: [u8; 32],
        identity: SessionIdentity,
        expires_at: OffsetDateTime,
    ) -> Self {
        Self {
            id,
            token_hash,
            identity,
            expires_at,
            last_seen_at: OffsetDateTime::now_utc(),
            mfa_verified: false,
            user_agent: None,
            ip_address: None,
            metadata: Metadata::empty(),
        }
    }

    pub fn last_seen_at(mut self, ts: OffsetDateTime) -> Self {
        self.last_seen_at = ts;
        self
    }

    pub fn mfa_verified(mut self, verified: bool) -> Self {
        self.mfa_verified = verified;
        self
    }

    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    pub fn ip_address(mut self, addr: impl Into<String>) -> Self {
        self.ip_address = Some(addr.into());
        self
    }

    pub fn metadata(mut self, meta: Metadata) -> Self {
        self.metadata = meta;
        self
    }

    pub fn build(self) -> Session {
        Session {
            id: self.id,
            token_hash: self.token_hash,
            identity: self.identity,
            expires_at: self.expires_at,
            last_seen_at: self.last_seen_at,
            mfa_verified: self.mfa_verified,
            user_agent: self.user_agent,
            ip_address: self.ip_address,
            metadata: self.metadata,
        }
    }
}

impl Session {
    pub fn builder(
        id: SessionId,
        token_hash: [u8; 32],
        identity: SessionIdentity,
        expires_at: OffsetDateTime,
    ) -> SessionBuilder {
        SessionBuilder::new(id, token_hash, identity, expires_at)
    }

    pub fn is_expired_at(&self, now: OffsetDateTime) -> bool {
        self.expires_at <= now
    }

    pub fn touch(&mut self) {
        self.touch_at(OffsetDateTime::now_utc());
    }

    pub fn touch_at(&mut self, now: OffsetDateTime) {
        self.last_seen_at = now;
    }

    pub fn mark_mfa_verified(&mut self) {
        self.mfa_verified = true;
    }

    pub const fn user_id(&self) -> Option<UserId> {
        match self.identity {
            SessionIdentity::User(id) => Some(id),
            SessionIdentity::Guest(_) => None,
        }
    }

    pub const fn guest_id(&self) -> Option<GuestId> {
        match self.identity {
            SessionIdentity::Guest(id) => Some(id),
            SessionIdentity::User(_) => None,
        }
    }
}
