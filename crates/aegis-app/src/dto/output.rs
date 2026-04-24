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
    pub roles: Option<Vec<String>>,
    pub mfa_verified: bool,
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
    pub uptime_seconds: u64,
    pub database: ComponentHealth,
    pub cache: ComponentHealth,
    pub email_enabled: bool,
    pub outbox_pending: u64,
}

#[derive(Debug, Clone)]
pub struct ComponentHealth {
    pub status: String,
    pub latency_ms: Option<u64>,
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct PaginatedResult<T> {
    pub items: Vec<T>,
    pub page: u32,
    pub per_page: u32,
    pub total: u64,
}

#[derive(Debug, Clone)]
pub struct AdminUserListItem {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    pub status: String,
    pub email_verified: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct UserSessionSummary {
    pub session_count: u64,
    pub last_seen_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone)]
pub struct AdminUserDetailResult {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    pub status: String,
    pub email_verified_at: Option<OffsetDateTime>,
    pub metadata: serde_json::Value,
    pub roles: Vec<String>,
    pub credentials: AdminUserCredentialSummary,
    pub session_count: u64,
    pub last_seen_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct AdminUserCredentialSummary {
    pub has_password: bool,
    pub passkey_count: u64,
    pub totp_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct OverviewStats {
    pub total_users: u64,
    pub active_users: u64,
    pub total_guests: u64,
    pub active_guests: u64,
    pub active_sessions: u64,
}

#[derive(Debug, Clone)]
pub struct AdminGuestListItem {
    pub id: Uuid,
    pub email: Option<String>,
    pub status: String,
    pub converted_to: Option<Uuid>,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct AdminGuestDetailResult {
    pub id: Uuid,
    pub email: Option<String>,
    pub status: String,
    pub converted_to: Option<Uuid>,
    pub metadata: serde_json::Value,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct AdminSessionListItem {
    pub id: Uuid,
    pub identity_type: String,
    pub identity_id: Uuid,
    pub expires_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
    pub mfa_verified: bool,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AdminSessionDetailResult {
    pub id: Uuid,
    pub identity_type: String,
    pub identity_id: Uuid,
    pub expires_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
    pub mfa_verified: bool,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub metadata: serde_json::Value,
}
