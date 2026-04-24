use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use time::{Duration, OffsetDateTime};
use tokio::sync::RwLock;
use uuid::Uuid;

use aegis_app::{
    AdminGuestDetailResult, AdminGuestListItem, AdminGuestListQuery,
    AdminSessionDetailResult, AdminSessionListItem, AdminSessionListQuery,
    AdminUserListItem, AdminUserListQuery, AegisApp, AppDeps, AppError,
    AppPolicies, AuditRepo, AuthPolicy, Cache, Clock, CompliancePolicy,
    CredentialRepo, CredentialSummary, CryptoPolicy, EmailPolicy, GuestRepo,
    Hasher, IdGenerator, JobPayload, OutboxEntry, OutboxRepo, PaginatedResult,
    PasskeyLoginFinishResult, PasskeyLoginStartResult, PasskeyPolicy,
    PasskeyRegisterFinishResult, PasskeyRegisterStartResult, PasswordHash,
    PasswordVerifyResult, PendingTokenRepo, RecoveryCodePolicy, RepoHealth,
    Repos, RoleRepo, SessionRepo, TokenGenerator, TotpPolicy, TransactionRepos,
    UserRepo, UserSessionSummary, WebAuthn, WebhookDispatcher,
};
use aegis_core::{
    Guest, GuestId, NewAuditEntry, PasskeyCredential, PasswordCredential,
    PendingToken, PendingTokenPurpose, RecoveryCode, Role, Session, SessionId,
    TotpCredential, User, UserId, UserRoleAssignment,
};

pub struct MockClock {
    now: Arc<RwLock<OffsetDateTime>>,
}

impl MockClock {
    pub fn new(now: OffsetDateTime) -> Self {
        Self {
            now: Arc::new(RwLock::new(now)),
        }
    }

    pub fn handle(&self) -> Arc<RwLock<OffsetDateTime>> {
        self.now.clone()
    }
}

impl Clock for MockClock {
    fn now(&self) -> OffsetDateTime {
        self.now
            .try_read()
            .map(|g| *g)
            .unwrap_or(OffsetDateTime::now_utc())
    }
}

pub struct MockIdGen {
    counter: Arc<std::sync::Mutex<u64>>,
}

impl MockIdGen {
    pub fn new() -> Self {
        Self {
            counter: Arc::new(std::sync::Mutex::new(0)),
        }
    }

    fn next_uuid(&self) -> Uuid {
        let mut c = self.counter.lock().unwrap();
        *c += 1;
        let val = *c;
        let mut bytes = [0u8; 16];
        bytes[0..8].copy_from_slice(&val.to_be_bytes());
        Uuid::from_bytes(bytes)
    }
}

impl IdGenerator for MockIdGen {
    fn user_id(&self) -> UserId {
        UserId::from_uuid(self.next_uuid())
    }
    fn guest_id(&self) -> GuestId {
        GuestId::from_uuid(self.next_uuid())
    }
    fn session_id(&self) -> SessionId {
        SessionId::from_uuid(self.next_uuid())
    }
    fn password_cred_id(&self) -> aegis_core::PasswordCredentialId {
        aegis_core::PasswordCredentialId::from_uuid(self.next_uuid())
    }
    fn passkey_cred_id(&self) -> aegis_core::PasskeyCredentialId {
        aegis_core::PasskeyCredentialId::from_uuid(self.next_uuid())
    }
    fn totp_cred_id(&self) -> aegis_core::TotpCredentialId {
        aegis_core::TotpCredentialId::from_uuid(self.next_uuid())
    }
    fn recovery_code_id(&self) -> aegis_core::RecoveryCodeId {
        aegis_core::RecoveryCodeId::from_uuid(self.next_uuid())
    }
    fn role_id(&self) -> aegis_core::RoleId {
        aegis_core::RoleId::from_uuid(self.next_uuid())
    }
    fn webhook_id(&self) -> aegis_core::WebhookId {
        aegis_core::WebhookId::from_uuid(self.next_uuid())
    }
}

pub struct MockTokenGen;

pub fn simple_hash(s: &str) -> [u8; 32] {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut hasher);
    let h = hasher.finish();
    let mut out = [0u8; 32];
    for chunk in out.chunks_exact_mut(8) {
        chunk.copy_from_slice(&h.to_be_bytes());
    }
    out
}

#[async_trait]
impl TokenGenerator for MockTokenGen {
    async fn generate_opaque(
        &self,
        _len: usize,
    ) -> Result<(String, [u8; 32]), AppError> {
        let token = format!("tok-{}", Uuid::now_v7());
        let hash = simple_hash(&token);
        Ok((token, hash))
    }

    async fn hash_token(&self, token: &str) -> [u8; 32] {
        simple_hash(token)
    }
}

pub struct MockHasher;

#[async_trait]
impl Hasher for MockHasher {
    fn current_algorithm_version(&self) -> u32 {
        1
    }

    async fn hash_password(
        &self,
        password: &str,
    ) -> Result<PasswordHash, AppError> {
        Ok(PasswordHash {
            hash: format!("hashed:{password}"),
            algorithm_version: 1,
        })
    }

    async fn verify_password(
        &self,
        password: &str,
        hash: &str,
        stored_version: u32,
    ) -> Result<PasswordVerifyResult, AppError> {
        if hash == format!("hashed:{password}") {
            if stored_version < self.current_algorithm_version() {
                Ok(PasswordVerifyResult::ValidButRehashNeeded {
                    current_version: self.current_algorithm_version(),
                })
            } else {
                Ok(PasswordVerifyResult::Valid)
            }
        } else {
            Ok(PasswordVerifyResult::Invalid)
        }
    }
}

pub struct MockCache;

#[async_trait]
impl Cache for MockCache {
    async fn get(&self, _key: &str) -> Result<Option<Vec<u8>>, AppError> {
        Ok(None)
    }
    async fn set(
        &self,
        _key: &str,
        _value: Vec<u8>,
        _ttl: Duration,
    ) -> Result<(), AppError> {
        Ok(())
    }
    async fn delete(&self, _key: &str) -> Result<(), AppError> {
        Ok(())
    }
}

pub struct MockWebhook;

#[async_trait]
impl WebhookDispatcher for MockWebhook {
    async fn dispatch(
        &self,
        _event: &str,
        _payload: &str,
    ) -> Result<(), AppError> {
        Ok(())
    }
}

pub struct MockWebAuthn;

#[async_trait]
impl WebAuthn for MockWebAuthn {
    async fn start_registration(
        &self,
        _user_id: &str,
        _user_name: &str,
        _display_name: &str,
        _exclude_credentials: Vec<String>,
    ) -> Result<PasskeyRegisterStartResult, AppError> {
        Ok(PasskeyRegisterStartResult {
            public_key: serde_json::json!({}),
            state: vec![],
        })
    }

    async fn finish_registration(
        &self,
        _state: &[u8],
        _response: &[u8],
    ) -> Result<PasskeyRegisterFinishResult, AppError> {
        Ok(PasskeyRegisterFinishResult {
            credential_id: "mock-cred-id".to_owned(),
            public_key: vec![],
            backup_eligible: false,
            backup_state: false,
            transports: vec![],
        })
    }

    async fn start_authentication(
        &self,
        _credentials: Vec<(String, Vec<u8>)>,
    ) -> Result<PasskeyLoginStartResult, AppError> {
        Ok(PasskeyLoginStartResult {
            public_key: serde_json::json!({}),
            state: vec![],
        })
    }

    async fn finish_authentication(
        &self,
        _state: &[u8],
        _response: &[u8],
    ) -> Result<PasskeyLoginFinishResult, AppError> {
        Ok(PasskeyLoginFinishResult {
            credential_id: "mock-cred-id".to_owned(),
            sign_count: 1,
        })
    }
}

#[derive(Default)]
pub struct MockState {
    pub users: HashMap<Uuid, User>,
    pub guests: HashMap<Uuid, Guest>,
    pub sessions: HashMap<[u8; 32], Session>,
    pub credentials_password: HashMap<Uuid, PasswordCredential>,
    pub credentials_totp: HashMap<Uuid, TotpCredential>,
    pub pending_tokens: Vec<PendingToken>,
    pub audits: Vec<NewAuditEntry>,
    pub outbox: Vec<JobPayload>,
    pub recovery_codes: HashMap<String, RecoveryCode>,
}

macro_rules! make_repo {
    ($name:ident) => {
        #[derive(Clone)]
        pub struct $name {
            state: Arc<RwLock<MockState>>,
        }
    };
}

make_repo!(MockUserRepo);
make_repo!(MockGuestRepo);
make_repo!(MockSessionRepo);
make_repo!(MockCredentialRepo);
make_repo!(MockPendingTokenRepo);
make_repo!(MockAuditRepo);
make_repo!(MockOutboxRepo);

#[derive(Clone)]
pub struct MockRoleRepo;

#[async_trait]
impl UserRepo for MockUserRepo {
    async fn get_by_id(&self, id: UserId) -> Result<Option<User>, AppError> {
        Ok(self.state.read().await.users.get(&id.as_uuid()).cloned())
    }
    async fn get_by_email(
        &self,
        email: &str,
    ) -> Result<Option<User>, AppError> {
        Ok(self
            .state
            .read()
            .await
            .users
            .values()
            .find(|u| u.email.as_str() == email)
            .cloned())
    }
    async fn list_admin(
        &self,
        query: &AdminUserListQuery,
    ) -> Result<PaginatedResult<AdminUserListItem>, AppError> {
        let state = self.state.read().await;
        let mut users = state.users.values().cloned().collect::<Vec<_>>();

        if let Some(status) = query.status.as_deref() {
            users.retain(|user| user.status.to_string() == status);
        }
        if let Some(verified) = query.verified {
            users.retain(|user| user.is_email_verified() == verified);
        }
        if let Some(search) = query.q.as_deref() {
            let search = search.to_lowercase();
            users.retain(|user| {
                user.email.as_str().to_lowercase().starts_with(&search)
                    || user
                        .display_name
                        .as_str()
                        .to_lowercase()
                        .starts_with(&search)
            });
        }

        users.sort_by_key(|user| user.created_at);
        if !matches!(query.order.as_deref(), Some("asc")) {
            users.reverse();
        }

        let page = query.page.max(1);
        let per_page = query.per_page.clamp(1, 200);
        let offset = ((page - 1) * per_page) as usize;
        let total = users.len() as u64;
        let items = users
            .into_iter()
            .skip(offset)
            .take(per_page as usize)
            .map(|user| AdminUserListItem {
                id: user.id.as_uuid(),
                email: user.email.as_str().to_owned(),
                display_name: user.display_name.as_str().to_owned(),
                status: user.status.to_string(),
                email_verified: user.is_email_verified(),
                created_at: user.created_at,
                updated_at: user.updated_at,
            })
            .collect();

        Ok(PaginatedResult {
            items,
            page,
            per_page,
            total,
        })
    }
    async fn email_exists(&self, email: &str) -> Result<bool, AppError> {
        Ok(self
            .state
            .read()
            .await
            .users
            .values()
            .any(|u| u.email.as_str() == email))
    }
    async fn count(&self) -> Result<u64, AppError> {
        Ok(self.state.read().await.users.len() as u64)
    }
    async fn count_by_status(&self, status: &str) -> Result<u64, AppError> {
        Ok(self
            .state
            .read()
            .await
            .users
            .values()
            .filter(|u| u.status.to_string() == status)
            .count() as u64)
    }
    async fn insert(&mut self, user: &User) -> Result<(), AppError> {
        self.state
            .write()
            .await
            .users
            .insert(user.id.as_uuid(), user.clone());
        Ok(())
    }
    async fn update(&mut self, user: &User) -> Result<(), AppError> {
        self.state
            .write()
            .await
            .users
            .insert(user.id.as_uuid(), user.clone());
        Ok(())
    }
}

#[async_trait]
impl GuestRepo for MockGuestRepo {
    async fn get_by_id(&self, id: GuestId) -> Result<Option<Guest>, AppError> {
        Ok(self.state.read().await.guests.get(&id.as_uuid()).cloned())
    }
    async fn list_admin(
        &self,
        query: &AdminGuestListQuery,
    ) -> Result<PaginatedResult<AdminGuestListItem>, AppError> {
        let state = self.state.read().await;
        let mut guests: Vec<_> = state.guests.values().cloned().collect();
        let now = OffsetDateTime::now_utc();

        if let Some(status) = query.status.as_deref() {
            guests.retain(|g| {
                let derived = if g.converted_to.is_some() {
                    "converted"
                } else if g.expires_at <= now {
                    "expired"
                } else {
                    "active"
                };
                derived == status
            });
        }

        guests.sort_by_key(|g| g.created_at);
        if !matches!(query.order.as_deref(), Some("asc")) {
            guests.reverse();
        }

        let page = query.page.max(1);
        let per_page = query.per_page.clamp(1, 200);
        let offset = ((page - 1) * per_page) as usize;
        let total = guests.len() as u64;
        let items = guests
            .into_iter()
            .skip(offset)
            .take(per_page as usize)
            .map(|g| {
                let status = if g.converted_to.is_some() {
                    "converted".to_owned()
                } else if g.expires_at <= now {
                    "expired".to_owned()
                } else {
                    "active".to_owned()
                };
                AdminGuestListItem {
                    id: g.id.as_uuid(),
                    email: g.email.as_ref().map(|e| e.as_str().to_owned()),
                    status,
                    converted_to: g.converted_to.map(|id| id.as_uuid()),
                    expires_at: g.expires_at,
                    created_at: g.created_at,
                    updated_at: g.updated_at,
                }
            })
            .collect();

        Ok(PaginatedResult {
            items,
            page,
            per_page,
            total,
        })
    }
    async fn get_admin_detail(
        &self,
        id: GuestId,
    ) -> Result<Option<AdminGuestDetailResult>, AppError> {
        let state = self.state.read().await;
        let g = match state.guests.get(&id.as_uuid()) {
            Some(g) => g,
            None => return Ok(None),
        };
        let now = OffsetDateTime::now_utc();
        let status = if g.converted_to.is_some() {
            "converted".to_owned()
        } else if g.expires_at <= now {
            "expired".to_owned()
        } else {
            "active".to_owned()
        };
        Ok(Some(AdminGuestDetailResult {
            id: g.id.as_uuid(),
            email: g.email.as_ref().map(|e| e.as_str().to_owned()),
            status,
            converted_to: g.converted_to.map(|id| id.as_uuid()),
            metadata: serde_json::from_str(g.metadata.as_str())
                .unwrap_or_default(),
            expires_at: g.expires_at,
            created_at: g.created_at,
            updated_at: g.updated_at,
        }))
    }
    async fn count(&self) -> Result<u64, AppError> {
        Ok(self.state.read().await.guests.len() as u64)
    }
    async fn count_active(&self) -> Result<u64, AppError> {
        let now = OffsetDateTime::now_utc();
        Ok(self
            .state
            .read()
            .await
            .guests
            .values()
            .filter(|g| g.converted_to.is_none() && g.expires_at > now)
            .count() as u64)
    }
    async fn insert(&mut self, guest: &Guest) -> Result<(), AppError> {
        self.state
            .write()
            .await
            .guests
            .insert(guest.id.as_uuid(), guest.clone());
        Ok(())
    }
    async fn update(&mut self, guest: &Guest) -> Result<(), AppError> {
        self.state
            .write()
            .await
            .guests
            .insert(guest.id.as_uuid(), guest.clone());
        Ok(())
    }
}

#[async_trait]
impl SessionRepo for MockSessionRepo {
    async fn get_by_id(
        &self,
        id: SessionId,
    ) -> Result<Option<Session>, AppError> {
        Ok(self
            .state
            .read()
            .await
            .sessions
            .values()
            .find(|session| session.id == id)
            .cloned())
    }
    async fn get_by_token_hash(
        &self,
        hash: &[u8; 32],
    ) -> Result<Option<Session>, AppError> {
        Ok(self.state.read().await.sessions.get(hash).cloned())
    }
    async fn get_user_summary(
        &self,
        user_id: UserId,
    ) -> Result<UserSessionSummary, AppError> {
        let state = self.state.read().await;
        let sessions = state
            .sessions
            .values()
            .filter(|session| session.user_id() == Some(user_id))
            .collect::<Vec<_>>();
        let last_seen_at =
            sessions.iter().map(|session| session.last_seen_at).max();
        Ok(UserSessionSummary {
            session_count: sessions.len() as u64,
            last_seen_at,
        })
    }
    async fn list_admin(
        &self,
        query: &AdminSessionListQuery,
    ) -> Result<PaginatedResult<AdminSessionListItem>, AppError> {
        let state = self.state.read().await;
        let now = OffsetDateTime::now_utc();
        let mut sessions: Vec<_> = state.sessions.values().cloned().collect();

        if let Some(user_id) = query.user_id {
            sessions
                .retain(|s| s.user_id() == Some(UserId::from_uuid(user_id)));
        }
        if query.active_only.unwrap_or(false) {
            sessions.retain(|s| s.expires_at > now);
        }

        sessions.sort_by_key(|s| std::cmp::Reverse(s.last_seen_at));

        let page = query.page.max(1);
        let per_page = query.per_page.clamp(1, 200);
        let offset = ((page - 1) * per_page) as usize;
        let total = sessions.len() as u64;
        let items = sessions
            .into_iter()
            .skip(offset)
            .take(per_page as usize)
            .map(|s| {
                let (identity_type, identity_id) = match s.identity {
                    aegis_core::SessionIdentity::User(uid) => {
                        ("user".to_owned(), uid.as_uuid())
                    }
                    aegis_core::SessionIdentity::Guest(gid) => {
                        ("guest".to_owned(), gid.as_uuid())
                    }
                };
                AdminSessionListItem {
                    id: s.id.as_uuid(),
                    identity_type,
                    identity_id,
                    expires_at: s.expires_at,
                    last_seen_at: s.last_seen_at,
                    mfa_verified: s.mfa_verified,
                    user_agent: s.user_agent.clone(),
                    ip_address: s.ip_address.clone(),
                }
            })
            .collect();

        Ok(PaginatedResult {
            items,
            page,
            per_page,
            total,
        })
    }
    async fn get_admin_detail(
        &self,
        id: SessionId,
    ) -> Result<Option<AdminSessionDetailResult>, AppError> {
        let state = self.state.read().await;
        let session = match state.sessions.values().find(|s| s.id == id) {
            Some(s) => s,
            None => return Ok(None),
        };
        let (identity_type, identity_id) = match session.identity {
            aegis_core::SessionIdentity::User(uid) => {
                ("user".to_owned(), uid.as_uuid())
            }
            aegis_core::SessionIdentity::Guest(gid) => {
                ("guest".to_owned(), gid.as_uuid())
            }
        };
        Ok(Some(AdminSessionDetailResult {
            id: session.id.as_uuid(),
            identity_type,
            identity_id,
            expires_at: session.expires_at,
            last_seen_at: session.last_seen_at,
            mfa_verified: session.mfa_verified,
            user_agent: session.user_agent.clone(),
            ip_address: session.ip_address.clone(),
            metadata: serde_json::from_str(session.metadata.as_str())
                .unwrap_or_default(),
        }))
    }
    async fn count_active(&self) -> Result<u64, AppError> {
        let now = OffsetDateTime::now_utc();
        Ok(self
            .state
            .read()
            .await
            .sessions
            .values()
            .filter(|s| s.expires_at > now)
            .count() as u64)
    }
    async fn insert(&mut self, session: &Session) -> Result<(), AppError> {
        self.state
            .write()
            .await
            .sessions
            .insert(session.token_hash, session.clone());
        Ok(())
    }
    async fn update(&mut self, session: &Session) -> Result<(), AppError> {
        self.state
            .write()
            .await
            .sessions
            .insert(session.token_hash, session.clone());
        Ok(())
    }
    async fn delete_by_id(&mut self, id: SessionId) -> Result<(), AppError> {
        self.state.write().await.sessions.retain(|_, s| s.id != id);
        Ok(())
    }
    async fn delete_by_user_id(
        &mut self,
        user_id: UserId,
    ) -> Result<(), AppError> {
        self.state
            .write()
            .await
            .sessions
            .retain(|_, s| s.user_id() != Some(user_id));
        Ok(())
    }
}

#[async_trait]
impl CredentialRepo for MockCredentialRepo {
    async fn get_password_by_user_id(
        &self,
        user_id: UserId,
    ) -> Result<Option<PasswordCredential>, AppError> {
        Ok(self
            .state
            .read()
            .await
            .credentials_password
            .get(&user_id.as_uuid())
            .cloned())
    }
    async fn list_by_user_id(
        &self,
        user_id: UserId,
    ) -> Result<Vec<CredentialSummary>, AppError> {
        let state = self.state.read().await;
        let mut summaries = Vec::new();
        if let Some(p) = state.credentials_password.get(&user_id.as_uuid()) {
            summaries.push(CredentialSummary {
                id: p.id.as_uuid(),
                kind: aegis_core::CredentialKind::Password,
                created_at: p.created_at,
                last_used_at: p.last_used_at,
            });
        }
        if let Some(t) = state.credentials_totp.get(&user_id.as_uuid()) {
            summaries.push(CredentialSummary {
                id: t.id.as_uuid(),
                kind: aegis_core::CredentialKind::Totp,
                created_at: t.created_at,
                last_used_at: None,
            });
        }
        Ok(summaries)
    }
    async fn get_totp_by_user_id(
        &self,
        user_id: UserId,
    ) -> Result<Option<TotpCredential>, AppError> {
        Ok(self
            .state
            .read()
            .await
            .credentials_totp
            .get(&user_id.as_uuid())
            .cloned())
    }
    async fn get_recovery_code_by_hash(
        &self,
        hash: &str,
    ) -> Result<Option<RecoveryCode>, AppError> {
        Ok(self.state.read().await.recovery_codes.get(hash).cloned())
    }
    async fn get_passkey_by_credential_id(
        &self,
        _cid: &str,
    ) -> Result<Option<PasskeyCredential>, AppError> {
        Ok(None)
    }
    async fn insert_password(
        &mut self,
        cred: &PasswordCredential,
    ) -> Result<(), AppError> {
        self.state
            .write()
            .await
            .credentials_password
            .insert(cred.user_id.as_uuid(), cred.clone());
        Ok(())
    }
    async fn update_password(
        &mut self,
        cred: &PasswordCredential,
    ) -> Result<(), AppError> {
        self.state
            .write()
            .await
            .credentials_password
            .insert(cred.user_id.as_uuid(), cred.clone());
        Ok(())
    }
    async fn delete_by_id(&mut self, _id: Uuid) -> Result<(), AppError> {
        Ok(())
    }
    async fn insert_totp(
        &mut self,
        cred: &TotpCredential,
    ) -> Result<(), AppError> {
        self.state
            .write()
            .await
            .credentials_totp
            .insert(cred.user_id.as_uuid(), cred.clone());
        Ok(())
    }
    async fn update_totp(
        &mut self,
        cred: &TotpCredential,
    ) -> Result<(), AppError> {
        self.state
            .write()
            .await
            .credentials_totp
            .insert(cred.user_id.as_uuid(), cred.clone());
        Ok(())
    }
    async fn insert_recovery_codes(
        &mut self,
        codes: &[RecoveryCode],
    ) -> Result<(), AppError> {
        let mut state = self.state.write().await;
        for code in codes {
            state
                .recovery_codes
                .insert(code.code_hash.clone(), code.clone());
        }
        Ok(())
    }
    async fn update_recovery_code(
        &mut self,
        code: &RecoveryCode,
    ) -> Result<(), AppError> {
        self.state
            .write()
            .await
            .recovery_codes
            .insert(code.code_hash.clone(), code.clone());
        Ok(())
    }
    async fn delete_recovery_codes_by_user_id(
        &mut self,
        uid: UserId,
    ) -> Result<(), AppError> {
        self.state
            .write()
            .await
            .recovery_codes
            .retain(|_, code| code.user_id != uid);
        Ok(())
    }
    async fn insert_passkey(
        &mut self,
        _cred: &PasskeyCredential,
    ) -> Result<(), AppError> {
        Ok(())
    }
    async fn update_passkey(
        &mut self,
        _cred: &PasskeyCredential,
    ) -> Result<(), AppError> {
        Ok(())
    }
}

#[async_trait]
impl RoleRepo for MockRoleRepo {
    async fn get_roles_by_user_id(
        &self,
        _uid: UserId,
    ) -> Result<Vec<Role>, AppError> {
        Ok(vec![])
    }
    async fn get_assignments_by_user_id(
        &self,
        _uid: UserId,
    ) -> Result<Vec<UserRoleAssignment>, AppError> {
        Ok(vec![])
    }
}

#[async_trait]
impl PendingTokenRepo for MockPendingTokenRepo {
    async fn get_by_hash(
        &self,
        hash: &[u8; 32],
        purpose: PendingTokenPurpose,
    ) -> Result<Option<PendingToken>, AppError> {
        Ok(self
            .state
            .read()
            .await
            .pending_tokens
            .iter()
            .find(|t| t.token_hash == *hash && t.purpose == purpose)
            .cloned())
    }
    async fn insert(&mut self, token: &PendingToken) -> Result<(), AppError> {
        self.state.write().await.pending_tokens.push(token.clone());
        Ok(())
    }
    async fn delete_by_hash(
        &mut self,
        hash: &[u8; 32],
    ) -> Result<(), AppError> {
        self.state
            .write()
            .await
            .pending_tokens
            .retain(|t| t.token_hash != *hash);
        Ok(())
    }
}

#[async_trait]
impl AuditRepo for MockAuditRepo {
    async fn insert(&mut self, entry: &NewAuditEntry) -> Result<(), AppError> {
        self.state.write().await.audits.push(entry.clone());
        Ok(())
    }
}

#[async_trait]
impl OutboxRepo for MockOutboxRepo {
    async fn enqueue(&mut self, payload: &JobPayload) -> Result<(), AppError> {
        self.state.write().await.outbox.push(payload.clone());
        Ok(())
    }
    async fn claim_pending(
        &mut self,
        _limit: usize,
    ) -> Result<Vec<OutboxEntry>, AppError> {
        Ok(vec![])
    }
    async fn mark_processed(&mut self, _id: i64) -> Result<(), AppError> {
        Ok(())
    }
    async fn mark_retry(
        &mut self,
        _id: i64,
        _next: OffsetDateTime,
    ) -> Result<(), AppError> {
        Ok(())
    }
    async fn mark_dead_lettered(&mut self, _id: i64) -> Result<(), AppError> {
        Ok(())
    }
}

pub struct MockTx {
    pub users: MockUserRepo,
    pub guests: MockGuestRepo,
    pub sessions: MockSessionRepo,
    pub credentials: MockCredentialRepo,
    pub roles: MockRoleRepo,
    pub tokens: MockPendingTokenRepo,
    pub audit: MockAuditRepo,
    pub outbox: MockOutboxRepo,
}

impl TransactionRepos for MockTx {
    type Users = MockUserRepo;
    type Guests = MockGuestRepo;
    type Sessions = MockSessionRepo;
    type Credentials = MockCredentialRepo;
    type Roles = MockRoleRepo;
    type Tokens = MockPendingTokenRepo;
    type Audit = MockAuditRepo;
    type Outbox = MockOutboxRepo;

    fn users(&mut self) -> &mut Self::Users {
        &mut self.users
    }
    fn guests(&mut self) -> &mut Self::Guests {
        &mut self.guests
    }
    fn sessions(&mut self) -> &mut Self::Sessions {
        &mut self.sessions
    }
    fn credentials(&mut self) -> &mut Self::Credentials {
        &mut self.credentials
    }
    fn roles(&mut self) -> &mut Self::Roles {
        &mut self.roles
    }
    fn tokens(&mut self) -> &mut Self::Tokens {
        &mut self.tokens
    }
    fn audit(&mut self) -> &mut Self::Audit {
        &mut self.audit
    }
    fn outbox(&mut self) -> &mut Self::Outbox {
        &mut self.outbox
    }
}

pub struct MockRepos {
    pub users: MockUserRepo,
    pub guests: MockGuestRepo,
    pub sessions: MockSessionRepo,
    pub credentials: MockCredentialRepo,
    pub roles: MockRoleRepo,
    pub tokens: MockPendingTokenRepo,
    pub audit: MockAuditRepo,
    pub outbox: MockOutboxRepo,
}

#[async_trait]
impl Repos for MockRepos {
    type Users = MockUserRepo;
    type Guests = MockGuestRepo;
    type Sessions = MockSessionRepo;
    type Credentials = MockCredentialRepo;
    type Roles = MockRoleRepo;
    type Tokens = MockPendingTokenRepo;
    type Audit = MockAuditRepo;
    type Outbox = MockOutboxRepo;
    type Tx = MockTx;

    fn users(&self) -> &Self::Users {
        &self.users
    }
    fn guests(&self) -> &Self::Guests {
        &self.guests
    }
    fn sessions(&self) -> &Self::Sessions {
        &self.sessions
    }
    fn credentials(&self) -> &Self::Credentials {
        &self.credentials
    }
    fn roles(&self) -> &Self::Roles {
        &self.roles
    }
    fn tokens(&self) -> &Self::Tokens {
        &self.tokens
    }
    fn audit(&self) -> &Self::Audit {
        &self.audit
    }
    fn outbox(&self) -> &Self::Outbox {
        &self.outbox
    }

    async fn with_transaction<F, Fut, T>(&self, f: F) -> Result<T, AppError>
    where
        F: FnOnce(Self::Tx) -> Fut + Send,
        Fut: std::future::Future<Output = (Self::Tx, Result<T, AppError>)>
            + Send,
        T: Send,
    {
        let tx = MockTx {
            users: self.users.clone(),
            guests: self.guests.clone(),
            sessions: self.sessions.clone(),
            credentials: self.credentials.clone(),
            roles: self.roles.clone(),
            tokens: self.tokens.clone(),
            audit: self.audit.clone(),
            outbox: self.outbox.clone(),
        };
        let (_tx, result) = f(tx).await;
        result
    }

    async fn health_check(&self) -> Result<RepoHealth, AppError> {
        Ok(RepoHealth {
            connected: true,
            latency_ms: 0,
            pool_size: 1,
            pool_idle: 1,
        })
    }
}

pub fn test_policies(email_enabled: bool) -> AppPolicies {
    use aegis_core::PasswordPolicy;
    AppPolicies {
        auth: AuthPolicy {
            session_max_age: Duration::hours(24),
            session_idle_timeout: Duration::hours(2),
            allow_unverified_login: !email_enabled,
            password_policy: PasswordPolicy {
                min_length: 8,
                require_uppercase: false,
                require_lowercase: false,
                require_digit: false,
                require_symbol: false,
                disallow_common: false,
                disallow_email_substring: false,
            },
            bearer_token_length: 32,
            bearer_default_ttl: Duration::minutes(15),
            refresh_token_enabled: false,
            refresh_token_ttl: Duration::days(30),
            revoke_all_sessions_on_password_reset: true,
        },
        email: EmailPolicy {
            enabled: email_enabled,
            verification_token_ttl: Duration::hours(24),
            password_reset_token_ttl: Duration::minutes(60),
        },
        crypto: CryptoPolicy {
            master_key: Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned()),
        },
        compliance: CompliancePolicy {
            guest_ttl: Duration::days(30),
            deleted_user_anonymize_after: Duration::days(90),
            anonymize_email_pattern: "deleted-{}@anonymized.local".to_owned(),
        },
        totp: TotpPolicy {
            issuer: "Aegis".to_owned(),
            period: 30,
            digits: 6,
            algorithm: aegis_core::TotpAlgorithm::Sha1,
            skew: 1,
        },
        recovery_codes: RecoveryCodePolicy {
            count: 8,
            code_length: 8,
        },
        passkeys: PasskeyPolicy {
            rp_id: None,
            rp_name: None,
            origins: vec![],
            timeout_seconds: 60,
        },
    }
}

pub fn test_ctx() -> aegis_app::RequestContext {
    aegis_app::RequestContext {
        ip_address: Some("127.0.0.1".to_owned()),
        user_agent: Some("test-agent".to_owned()),
        request_id: Some(Uuid::now_v7()),
    }
}

pub type TestApp = AegisApp<
    MockRepos,
    MockCache,
    MockHasher,
    MockTokenGen,
    MockWebhook,
    MockClock,
    MockIdGen,
    MockWebAuthn,
>;

pub fn make_app(
    clock: &MockClock,
    email_enabled: bool,
) -> (TestApp, Arc<RwLock<MockState>>) {
    let state = Arc::new(RwLock::new(MockState::default()));
    let repos = MockRepos {
        users: MockUserRepo {
            state: state.clone(),
        },
        guests: MockGuestRepo {
            state: state.clone(),
        },
        sessions: MockSessionRepo {
            state: state.clone(),
        },
        credentials: MockCredentialRepo {
            state: state.clone(),
        },
        roles: MockRoleRepo,
        tokens: MockPendingTokenRepo {
            state: state.clone(),
        },
        audit: MockAuditRepo {
            state: state.clone(),
        },
        outbox: MockOutboxRepo {
            state: state.clone(),
        },
    };
    let deps = AppDeps {
        repos,
        cache: MockCache,
        hasher: MockHasher,
        tokens: MockTokenGen,
        webhooks: MockWebhook,
        clock: MockClock {
            now: clock.handle(),
        },
        ids: MockIdGen::new(),
        webauthn: MockWebAuthn,
    };
    let app = AegisApp::new(deps, test_policies(email_enabled));
    (app, state)
}
