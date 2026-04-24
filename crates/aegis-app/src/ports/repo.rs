use std::future::Future;

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use aegis_core::{
    Guest, GuestId, NewAuditEntry, PasskeyCredential, PasswordCredential,
    PendingToken, PendingTokenPurpose, RecoveryCode, Role, Session, SessionId,
    TotpCredential, User, UserId, UserRoleAssignment,
};

use crate::dto::{
    AdminGuestDetailResult, AdminGuestListItem, AdminGuestListQuery,
    AdminSessionDetailResult, AdminSessionListItem, AdminSessionListQuery,
    AdminUserListItem, AdminUserListQuery, CredentialSummary, PaginatedResult,
    UserSessionSummary,
};
use crate::error::AppError;
use crate::jobs::JobPayload;

#[async_trait]
pub trait UserRepo: Send + Sync {
    async fn get_by_id(&self, id: UserId) -> Result<Option<User>, AppError>;
    async fn get_by_email(&self, email: &str)
    -> Result<Option<User>, AppError>;
    async fn list_admin(
        &self,
        query: &AdminUserListQuery,
    ) -> Result<PaginatedResult<AdminUserListItem>, AppError>;
    async fn count(&self) -> Result<u64, AppError>;
    async fn count_by_status(&self, status: &str) -> Result<u64, AppError>;
    async fn email_exists(&self, email: &str) -> Result<bool, AppError>;
    async fn insert(&mut self, user: &User) -> Result<(), AppError>;
    async fn update(&mut self, user: &User) -> Result<(), AppError>;
}

#[async_trait]
pub trait GuestRepo: Send + Sync {
    async fn get_by_id(&self, id: GuestId) -> Result<Option<Guest>, AppError>;
    async fn list_admin(
        &self,
        query: &AdminGuestListQuery,
    ) -> Result<PaginatedResult<AdminGuestListItem>, AppError>;
    async fn get_admin_detail(
        &self,
        id: GuestId,
    ) -> Result<Option<AdminGuestDetailResult>, AppError>;
    async fn count(&self) -> Result<u64, AppError>;
    async fn count_active(&self) -> Result<u64, AppError>;
    async fn insert(&mut self, guest: &Guest) -> Result<(), AppError>;
    async fn update(&mut self, guest: &Guest) -> Result<(), AppError>;
}

#[async_trait]
pub trait SessionRepo: Send + Sync {
    async fn get_by_id(
        &self,
        id: SessionId,
    ) -> Result<Option<Session>, AppError>;
    async fn get_by_token_hash(
        &self,
        hash: &[u8; 32],
    ) -> Result<Option<Session>, AppError>;
    async fn get_user_summary(
        &self,
        user_id: UserId,
    ) -> Result<UserSessionSummary, AppError>;
    async fn list_admin(
        &self,
        query: &AdminSessionListQuery,
    ) -> Result<PaginatedResult<AdminSessionListItem>, AppError>;
    async fn get_admin_detail(
        &self,
        id: SessionId,
    ) -> Result<Option<AdminSessionDetailResult>, AppError>;
    async fn count_active(&self) -> Result<u64, AppError>;
    async fn insert(&mut self, session: &Session) -> Result<(), AppError>;
    async fn update(&mut self, session: &Session) -> Result<(), AppError>;
    async fn delete_by_id(&mut self, id: SessionId) -> Result<(), AppError>;
    async fn delete_by_user_id(
        &mut self,
        user_id: UserId,
    ) -> Result<(), AppError>;
}

#[async_trait]
pub trait CredentialRepo: Send + Sync {
    async fn get_password_by_user_id(
        &self,
        user_id: UserId,
    ) -> Result<Option<PasswordCredential>, AppError>;
    async fn list_by_user_id(
        &self,
        user_id: UserId,
    ) -> Result<Vec<CredentialSummary>, AppError>;
    async fn get_totp_by_user_id(
        &self,
        user_id: UserId,
    ) -> Result<Option<TotpCredential>, AppError>;
    async fn get_recovery_code_by_hash(
        &self,
        hash: &str,
    ) -> Result<Option<RecoveryCode>, AppError>;
    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> Result<Option<PasskeyCredential>, AppError>;
    async fn insert_password(
        &mut self,
        cred: &PasswordCredential,
    ) -> Result<(), AppError>;
    async fn update_password(
        &mut self,
        cred: &PasswordCredential,
    ) -> Result<(), AppError>;
    async fn delete_by_id(&mut self, id: Uuid) -> Result<(), AppError>;
    async fn insert_totp(
        &mut self,
        cred: &TotpCredential,
    ) -> Result<(), AppError>;
    async fn update_totp(
        &mut self,
        cred: &TotpCredential,
    ) -> Result<(), AppError>;
    async fn insert_recovery_codes(
        &mut self,
        codes: &[RecoveryCode],
    ) -> Result<(), AppError>;
    async fn update_recovery_code(
        &mut self,
        code: &RecoveryCode,
    ) -> Result<(), AppError>;
    async fn delete_recovery_codes_by_user_id(
        &mut self,
        user_id: UserId,
    ) -> Result<(), AppError>;
    async fn insert_passkey(
        &mut self,
        cred: &PasskeyCredential,
    ) -> Result<(), AppError>;
    async fn update_passkey(
        &mut self,
        cred: &PasskeyCredential,
    ) -> Result<(), AppError>;
}

#[async_trait]
pub trait RoleRepo: Send + Sync {
    async fn get_roles_by_user_id(
        &self,
        user_id: UserId,
    ) -> Result<Vec<Role>, AppError>;
    async fn get_assignments_by_user_id(
        &self,
        user_id: UserId,
    ) -> Result<Vec<UserRoleAssignment>, AppError>;
}

#[async_trait]
pub trait PendingTokenRepo: Send + Sync {
    async fn get_by_hash(
        &self,
        hash: &[u8; 32],
        purpose: PendingTokenPurpose,
    ) -> Result<Option<PendingToken>, AppError>;
    async fn insert(&mut self, token: &PendingToken) -> Result<(), AppError>;
    async fn delete_by_hash(&mut self, hash: &[u8; 32])
    -> Result<(), AppError>;
}

#[async_trait]
pub trait AuditRepo: Send + Sync {
    async fn insert(&mut self, entry: &NewAuditEntry) -> Result<(), AppError>;
}

#[derive(Debug, Clone)]
pub struct OutboxEntry {
    pub id: i64,
    pub job_type: String,
    pub payload: String,
    pub attempts: u32,
    pub max_attempts: u32,
    pub created_at: OffsetDateTime,
    pub next_retry_at: Option<OffsetDateTime>,
}

#[async_trait]
pub trait OutboxRepo: Send + Sync {
    async fn enqueue(&mut self, payload: &JobPayload) -> Result<(), AppError>;
    async fn claim_pending(
        &mut self,
        limit: usize,
    ) -> Result<Vec<OutboxEntry>, AppError>;
    async fn mark_processed(&mut self, id: i64) -> Result<(), AppError>;
    async fn mark_retry(
        &mut self,
        id: i64,
        next_retry_at: OffsetDateTime,
    ) -> Result<(), AppError>;
    async fn mark_dead_lettered(&mut self, id: i64) -> Result<(), AppError>;
}

pub trait TransactionRepos: Send {
    type Users: UserRepo;
    type Guests: GuestRepo;
    type Sessions: SessionRepo;
    type Credentials: CredentialRepo;
    type Roles: RoleRepo;
    type Tokens: PendingTokenRepo;
    type Audit: AuditRepo;
    type Outbox: OutboxRepo;

    fn users(&mut self) -> &mut Self::Users;
    fn guests(&mut self) -> &mut Self::Guests;
    fn sessions(&mut self) -> &mut Self::Sessions;
    fn credentials(&mut self) -> &mut Self::Credentials;
    fn roles(&mut self) -> &mut Self::Roles;
    fn tokens(&mut self) -> &mut Self::Tokens;
    fn audit(&mut self) -> &mut Self::Audit;
    fn outbox(&mut self) -> &mut Self::Outbox;
}

#[async_trait]
pub trait Repos: Send + Sync {
    type Users: UserRepo;
    type Guests: GuestRepo;
    type Sessions: SessionRepo;
    type Credentials: CredentialRepo;
    type Roles: RoleRepo;
    type Tokens: PendingTokenRepo;
    type Audit: AuditRepo;
    type Outbox: OutboxRepo;

    type Tx: TransactionRepos;

    fn users(&self) -> &Self::Users;
    fn guests(&self) -> &Self::Guests;
    fn sessions(&self) -> &Self::Sessions;
    fn credentials(&self) -> &Self::Credentials;
    fn roles(&self) -> &Self::Roles;
    fn tokens(&self) -> &Self::Tokens;
    fn audit(&self) -> &Self::Audit;
    fn outbox(&self) -> &Self::Outbox;

    async fn with_transaction<F, Fut, T>(&self, f: F) -> Result<T, AppError>
    where
        F: FnOnce(Self::Tx) -> Fut + Send,
        Fut: Future<Output = (Self::Tx, Result<T, AppError>)> + Send,
        T: Send;

    async fn health_check(&self) -> Result<RepoHealth, AppError>;
}

#[derive(Debug, Clone)]
pub struct RepoHealth {
    pub connected: bool,
    pub latency_ms: u64,
    pub pool_size: u32,
    pub pool_idle: u32,
}
