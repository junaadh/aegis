use std::fmt;
use time::OffsetDateTime;
use uuid::Uuid;

use aegis_core::{CredentialKind, Guest, GuestId, Role, User, UserId};

#[derive(Debug)]
pub enum LoginOutcome {
    Authenticated(AuthResult),
    RequiresMfa {
        session_token: String,
        session_expires_at: OffsetDateTime,
    },
}

#[derive(Debug)]
pub struct AuthResult {
    pub user: User,
    pub session_token: String,
    pub session_expires_at: OffsetDateTime,
    pub mfa_verified: bool,
}

#[derive(Debug)]
pub struct GuestAuthResult {
    pub guest: Guest,
    pub session_token: String,
    pub session_expires_at: OffsetDateTime,
}

#[derive(Debug)]
pub struct IdentityResult {
    pub user: Option<User>,
    pub guest: Option<Guest>,
    pub roles: Vec<Role>,
    pub credentials: Vec<CredentialSummary>,
}

#[derive(Debug, Clone)]
pub struct CredentialSummary {
    pub id: Uuid,
    pub kind: CredentialKind,
    pub created_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
}

impl fmt::Display for CredentialSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.kind, self.id)
    }
}

#[derive(Debug)]
pub struct TotpEnrollResult {
    pub secret: String,
    pub qr_code_url: String,
    pub recovery_codes: Vec<String>,
}

#[derive(Debug)]
pub struct SessionValidateResult {
    pub valid: bool,
    pub user_id: Option<UserId>,
    pub guest_id: Option<GuestId>,
    pub status: Option<String>,
    pub expires_at: Option<OffsetDateTime>,
}

#[derive(Debug)]
pub struct UserLookupResult {
    pub id: Uuid,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub status: String,
    pub email_verified: Option<bool>,
    pub roles: Option<Vec<String>>,
    pub metadata: Option<String>,
}

#[derive(Debug)]
pub struct HealthResult {
    pub status: String,
    pub version: String,
    pub database_connected: bool,
}
