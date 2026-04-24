use std::sync::Arc;

use aegis_app::{
    AdminGuestDetailResult, AdminGuestListItem, AdminGuestListQuery,
    AdminSessionDetailResult, AdminSessionListItem, AdminSessionListQuery,
    AdminUserListItem, AdminUserListQuery, AppDeps, AppError, AppPolicies,
    AuditRepo, Cache, CredentialRepo, GuestRepo, Hasher, OutboxEntry,
    OutboxRepo, PaginatedResult, PasswordHash, PasswordVerifyResult,
    PendingTokenRepo, RepoHealth, Repos, RoleRepo, SessionRepo,
    TransactionRepos, UserRepo, UserSessionSummary, WebAuthn,
};
use aegis_config::{Config, JwtAlgorithm};
use aegis_core::{
    Guest, GuestId, NewAuditEntry, PasskeyCredential, PasswordCredential,
    PendingToken, PendingTokenPurpose, RecoveryCode, Role, Session, SessionId,
    TotpCredential, User, UserId, UserRoleAssignment,
};
use aegis_http::{
    AppHandle, app_router, auth_context_middleware, internal_auth_middleware,
    internal_network_guard, request_id_middleware,
};
use aegis_infra::{
    JwtIssuer, JwtVerifier, NoopWebhookDispatcher, SystemClock,
    SystemTokenGenerator, UuidV7IdGenerator,
};
use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use axum::middleware;
use axum::response::Response;
use ipnet::IpNet;
use serde_json::Value;
use std::net::SocketAddr;
use tower::ServiceExt;

struct DummyCache;

#[async_trait::async_trait]
impl Cache for DummyCache {
    async fn get(&self, _key: &str) -> Result<Option<Vec<u8>>, AppError> {
        panic!("unused in envelope tests")
    }

    async fn set(
        &self,
        _key: &str,
        _value: Vec<u8>,
        _ttl: time::Duration,
    ) -> Result<(), AppError> {
        panic!("unused in envelope tests")
    }

    async fn delete(&self, _key: &str) -> Result<(), AppError> {
        panic!("unused in envelope tests")
    }

    async fn ping(&self) -> Result<(), AppError> {
        Ok(())
    }
}

struct DummyHasher;

#[async_trait::async_trait]
impl Hasher for DummyHasher {
    fn current_algorithm_version(&self) -> u32 {
        1
    }

    async fn hash_password(
        &self,
        _password: &str,
    ) -> Result<PasswordHash, AppError> {
        panic!("unused in envelope tests")
    }

    async fn verify_password(
        &self,
        _password: &str,
        _hash: &str,
        _stored_version: u32,
    ) -> Result<PasswordVerifyResult, AppError> {
        panic!("unused in envelope tests")
    }
}

struct DummyWebAuthn;

#[async_trait::async_trait]
impl WebAuthn for DummyWebAuthn {
    async fn start_registration(
        &self,
        _user_id: &str,
        _user_name: &str,
        _display_name: &str,
        _exclude_credentials: Vec<String>,
    ) -> Result<aegis_app::PasskeyRegisterStartResult, AppError> {
        panic!("unused in envelope tests")
    }

    async fn finish_registration(
        &self,
        _state: &[u8],
        _response: &[u8],
    ) -> Result<aegis_app::PasskeyRegisterFinishResult, AppError> {
        panic!("unused in envelope tests")
    }

    async fn start_authentication(
        &self,
        _credentials: Vec<(String, Vec<u8>)>,
    ) -> Result<aegis_app::PasskeyLoginStartResult, AppError> {
        panic!("unused in envelope tests")
    }

    async fn finish_authentication(
        &self,
        _state: &[u8],
        _response: &[u8],
    ) -> Result<aegis_app::PasskeyLoginFinishResult, AppError> {
        panic!("unused in envelope tests")
    }
}

#[derive(Default)]
struct DummyUsers;

#[async_trait::async_trait]
impl UserRepo for DummyUsers {
    async fn get_by_id(&self, _id: UserId) -> Result<Option<User>, AppError> {
        panic!("unused")
    }
    async fn get_by_email(
        &self,
        _email: &str,
    ) -> Result<Option<User>, AppError> {
        panic!("unused")
    }
    async fn list_admin(
        &self,
        _query: &AdminUserListQuery,
    ) -> Result<PaginatedResult<AdminUserListItem>, AppError> {
        Ok(PaginatedResult {
            items: vec![],
            page: 1,
            per_page: 50,
            total: 0,
        })
    }
    async fn email_exists(&self, _email: &str) -> Result<bool, AppError> {
        panic!("unused")
    }
    async fn count(&self) -> Result<u64, AppError> {
        Ok(0)
    }
    async fn count_by_status(&self, _status: &str) -> Result<u64, AppError> {
        Ok(0)
    }
    async fn insert(&mut self, _user: &User) -> Result<(), AppError> {
        panic!("unused")
    }
    async fn update(&mut self, _user: &User) -> Result<(), AppError> {
        panic!("unused")
    }
}

#[derive(Default)]
struct DummyGuests;

#[async_trait::async_trait]
impl GuestRepo for DummyGuests {
    async fn get_by_id(&self, _id: GuestId) -> Result<Option<Guest>, AppError> {
        panic!("unused")
    }
    async fn list_admin(
        &self,
        _query: &AdminGuestListQuery,
    ) -> Result<PaginatedResult<AdminGuestListItem>, AppError> {
        Ok(PaginatedResult {
            items: vec![],
            page: 1,
            per_page: 50,
            total: 0,
        })
    }
    async fn get_admin_detail(
        &self,
        _id: GuestId,
    ) -> Result<Option<AdminGuestDetailResult>, AppError> {
        Ok(None)
    }
    async fn count(&self) -> Result<u64, AppError> {
        Ok(0)
    }
    async fn count_active(&self) -> Result<u64, AppError> {
        Ok(0)
    }
    async fn insert(&mut self, _guest: &Guest) -> Result<(), AppError> {
        panic!("unused")
    }
    async fn update(&mut self, _guest: &Guest) -> Result<(), AppError> {
        panic!("unused")
    }
}

#[derive(Default)]
struct DummySessions;

#[async_trait::async_trait]
impl SessionRepo for DummySessions {
    async fn get_by_id(
        &self,
        _id: SessionId,
    ) -> Result<Option<Session>, AppError> {
        panic!("unused")
    }
    async fn get_by_token_hash(
        &self,
        _hash: &[u8; 32],
    ) -> Result<Option<Session>, AppError> {
        Ok(None)
    }
    async fn get_user_summary(
        &self,
        _user_id: UserId,
    ) -> Result<UserSessionSummary, AppError> {
        Ok(UserSessionSummary {
            session_count: 0,
            last_seen_at: None,
        })
    }
    async fn list_admin(
        &self,
        _query: &AdminSessionListQuery,
    ) -> Result<PaginatedResult<AdminSessionListItem>, AppError> {
        Ok(PaginatedResult {
            items: vec![],
            page: 1,
            per_page: 50,
            total: 0,
        })
    }
    async fn get_admin_detail(
        &self,
        _id: SessionId,
    ) -> Result<Option<AdminSessionDetailResult>, AppError> {
        Ok(None)
    }
    async fn count_active(&self) -> Result<u64, AppError> {
        Ok(0)
    }
    async fn insert(&mut self, _session: &Session) -> Result<(), AppError> {
        panic!("unused")
    }
    async fn update(&mut self, _session: &Session) -> Result<(), AppError> {
        panic!("unused")
    }
    async fn delete_by_id(&mut self, _id: SessionId) -> Result<(), AppError> {
        panic!("unused")
    }
    async fn delete_by_user_id(
        &mut self,
        _user_id: UserId,
    ) -> Result<(), AppError> {
        panic!("unused")
    }
}

#[derive(Default)]
struct DummyCredentials;

#[async_trait::async_trait]
impl CredentialRepo for DummyCredentials {
    async fn get_password_by_user_id(
        &self,
        _user_id: UserId,
    ) -> Result<Option<PasswordCredential>, AppError> {
        panic!("unused")
    }
    async fn list_by_user_id(
        &self,
        _user_id: UserId,
    ) -> Result<Vec<aegis_app::CredentialSummary>, AppError> {
        panic!("unused")
    }
    async fn get_totp_by_user_id(
        &self,
        _user_id: UserId,
    ) -> Result<Option<TotpCredential>, AppError> {
        panic!("unused")
    }
    async fn get_recovery_code_by_hash(
        &self,
        _hash: &str,
    ) -> Result<Option<RecoveryCode>, AppError> {
        panic!("unused")
    }
    async fn get_passkey_by_credential_id(
        &self,
        _credential_id: &str,
    ) -> Result<Option<PasskeyCredential>, AppError> {
        panic!("unused")
    }
    async fn insert_password(
        &mut self,
        _cred: &PasswordCredential,
    ) -> Result<(), AppError> {
        panic!("unused")
    }
    async fn update_password(
        &mut self,
        _cred: &PasswordCredential,
    ) -> Result<(), AppError> {
        panic!("unused")
    }
    async fn delete_by_id(&mut self, _id: uuid::Uuid) -> Result<(), AppError> {
        panic!("unused")
    }
    async fn insert_totp(
        &mut self,
        _cred: &TotpCredential,
    ) -> Result<(), AppError> {
        panic!("unused")
    }
    async fn update_totp(
        &mut self,
        _cred: &TotpCredential,
    ) -> Result<(), AppError> {
        panic!("unused")
    }
    async fn insert_recovery_codes(
        &mut self,
        _codes: &[RecoveryCode],
    ) -> Result<(), AppError> {
        panic!("unused")
    }
    async fn update_recovery_code(
        &mut self,
        _code: &RecoveryCode,
    ) -> Result<(), AppError> {
        panic!("unused")
    }
    async fn delete_recovery_codes_by_user_id(
        &mut self,
        _user_id: UserId,
    ) -> Result<(), AppError> {
        panic!("unused")
    }
    async fn insert_passkey(
        &mut self,
        _cred: &PasskeyCredential,
    ) -> Result<(), AppError> {
        panic!("unused")
    }
    async fn update_passkey(
        &mut self,
        _cred: &PasskeyCredential,
    ) -> Result<(), AppError> {
        panic!("unused")
    }
}

#[derive(Default)]
struct DummyRoles;

#[async_trait::async_trait]
impl RoleRepo for DummyRoles {
    async fn get_roles_by_user_id(
        &self,
        _user_id: UserId,
    ) -> Result<Vec<Role>, AppError> {
        panic!("unused")
    }
    async fn get_assignments_by_user_id(
        &self,
        _user_id: UserId,
    ) -> Result<Vec<UserRoleAssignment>, AppError> {
        panic!("unused")
    }
}

#[derive(Default)]
struct DummyTokens;

#[async_trait::async_trait]
impl PendingTokenRepo for DummyTokens {
    async fn get_by_hash(
        &self,
        _hash: &[u8; 32],
        _purpose: PendingTokenPurpose,
    ) -> Result<Option<PendingToken>, AppError> {
        panic!("unused")
    }
    async fn insert(&mut self, _token: &PendingToken) -> Result<(), AppError> {
        panic!("unused")
    }
    async fn delete_by_hash(
        &mut self,
        _hash: &[u8; 32],
    ) -> Result<(), AppError> {
        panic!("unused")
    }
}

#[derive(Default)]
struct DummyAudit;

#[async_trait::async_trait]
impl AuditRepo for DummyAudit {
    async fn insert(&mut self, _entry: &NewAuditEntry) -> Result<(), AppError> {
        panic!("unused")
    }
}

#[derive(Default)]
struct DummyOutbox;

#[async_trait::async_trait]
impl OutboxRepo for DummyOutbox {
    async fn enqueue(
        &mut self,
        _payload: &aegis_app::JobPayload,
    ) -> Result<(), AppError> {
        panic!("unused")
    }
    async fn claim_pending(
        &mut self,
        _limit: usize,
    ) -> Result<Vec<OutboxEntry>, AppError> {
        panic!("unused")
    }
    async fn mark_processed(&mut self, _id: i64) -> Result<(), AppError> {
        panic!("unused")
    }
    async fn mark_retry(
        &mut self,
        _id: i64,
        _next_retry_at: time::OffsetDateTime,
    ) -> Result<(), AppError> {
        panic!("unused")
    }
    async fn mark_dead_lettered(&mut self, _id: i64) -> Result<(), AppError> {
        panic!("unused")
    }
}

#[derive(Default)]
struct DummyTx {
    users: DummyUsers,
    guests: DummyGuests,
    sessions: DummySessions,
    credentials: DummyCredentials,
    roles: DummyRoles,
    tokens: DummyTokens,
    audit: DummyAudit,
    outbox: DummyOutbox,
}

impl TransactionRepos for DummyTx {
    type Users = DummyUsers;
    type Guests = DummyGuests;
    type Sessions = DummySessions;
    type Credentials = DummyCredentials;
    type Roles = DummyRoles;
    type Tokens = DummyTokens;
    type Audit = DummyAudit;
    type Outbox = DummyOutbox;

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

#[derive(Default)]
struct DummyRepos {
    users: DummyUsers,
    guests: DummyGuests,
    sessions: DummySessions,
    credentials: DummyCredentials,
    roles: DummyRoles,
    tokens: DummyTokens,
    audit: DummyAudit,
    outbox: DummyOutbox,
}

#[async_trait::async_trait]
impl Repos for DummyRepos {
    type Users = DummyUsers;
    type Guests = DummyGuests;
    type Sessions = DummySessions;
    type Credentials = DummyCredentials;
    type Roles = DummyRoles;
    type Tokens = DummyTokens;
    type Audit = DummyAudit;
    type Outbox = DummyOutbox;
    type Tx = DummyTx;

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

    async fn with_transaction<F, Fut, T>(&self, _f: F) -> Result<T, AppError>
    where
        F: FnOnce(Self::Tx) -> Fut + Send,
        Fut: std::future::Future<Output = (Self::Tx, Result<T, AppError>)>
            + Send,
        T: Send,
    {
        panic!("unused")
    }

    async fn health_check(&self) -> Result<RepoHealth, AppError> {
        Ok(RepoHealth {
            connected: true,
            latency_ms: 1,
            pool_size: 1,
            pool_idle: 1,
        })
    }
}

fn test_config() -> Config {
    let mut config = Config::default();
    config.crypto.jwt.enabled = true;
    config.crypto.jwt.algorithm = JwtAlgorithm::RS256;
    config.crypto.jwt.issuer = Some("aegis".to_owned());
    config.crypto.jwt.audience = Some("aegis-internal".to_owned());
    config.crypto.jwt.private_key = Some(RSA_PRIVATE_KEY.to_owned());
    config.crypto.jwt.public_key = Some(RSA_PUBLIC_KEY.to_owned());
    config
}

fn test_app() -> axum::Router {
    test_app_with_cidrs(&[])
}

fn test_app_with_cidrs(cidrs: &[&str]) -> axum::Router {
    let config = test_config();
    let policies = AppPolicies::from_config(&config).unwrap();
    let verifier = JwtVerifier::from_config(&config).unwrap().map(Arc::new);
    let internal_allowed_cidrs = cidrs
        .iter()
        .map(|cidr| cidr.parse::<IpNet>().unwrap())
        .collect::<Vec<_>>();

    let app = aegis_app::AegisApp::new(
        AppDeps {
            repos: DummyRepos::default(),
            cache: DummyCache,
            hasher: DummyHasher,
            tokens: SystemTokenGenerator::new(),
            webhooks: NoopWebhookDispatcher::new(),
            clock: SystemClock::new(),
            ids: UuidV7IdGenerator::new(),
            webauthn: DummyWebAuthn,
        },
        policies,
    );

    let state = Arc::new(AppHandle {
        app,
        config: config.clone(),
        internal_allowed_cidrs: Arc::new(internal_allowed_cidrs),
        internal_jwt_verifier: verifier,
        started_at: std::time::Instant::now(),
    });

    type TestState = aegis_http::AppState<
        DummyRepos,
        DummyCache,
        DummyHasher,
        SystemTokenGenerator,
        NoopWebhookDispatcher,
        SystemClock,
        UuidV7IdGenerator,
        DummyWebAuthn,
    >;

    async fn auth_middleware_for_tests(
        State(state): State<TestState>,
        request: Request<Body>,
        next: middleware::Next,
    ) -> Response {
        auth_context_middleware(state, request, next).await
    }

    async fn internal_middleware_for_tests(
        State(state): State<TestState>,
        request: Request<Body>,
        next: middleware::Next,
    ) -> Response {
        internal_auth_middleware(state, request, next).await
    }

    async fn internal_network_guard_for_tests(
        State(state): State<TestState>,
        request: Request<Body>,
        next: middleware::Next,
    ) -> Response {
        internal_network_guard(state, request, next).await
    }

    app_router::<
        DummyRepos,
        DummyCache,
        DummyHasher,
        SystemTokenGenerator,
        NoopWebhookDispatcher,
        SystemClock,
        UuidV7IdGenerator,
        DummyWebAuthn,
    >()
    .with_state(state.clone())
    .layer(middleware::from_fn_with_state(
        state.clone(),
        auth_middleware_for_tests,
    ))
    .layer(middleware::from_fn_with_state(
        state.clone(),
        internal_middleware_for_tests,
    ))
    .layer(middleware::from_fn_with_state(
        state,
        internal_network_guard_for_tests,
    ))
    .layer(middleware::from_fn(request_id_middleware))
}

fn internal_jwt(scopes: &[&str]) -> String {
    let config = test_config();
    let issuer = JwtIssuer::from_config(&config).unwrap().unwrap();
    let scopes = scopes
        .iter()
        .map(|scope| scope.parse().unwrap())
        .collect::<Vec<_>>();
    issuer
        .issue_service_token(
            "service:test-harness",
            scopes,
            time::Duration::days(1),
            time::OffsetDateTime::now_utc(),
        )
        .unwrap()
}

async fn send(
    app: &axum::Router,
    method: Method,
    path: &str,
    body: Option<&str>,
    headers: &[(&str, &str)],
    remote_addr: Option<SocketAddr>,
) -> (StatusCode, Value) {
    let mut request = Request::builder().method(method).uri(path);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let mut request = request
        .body(match body {
            Some(body) => Body::from(body.to_owned()),
            None => Body::empty(),
        })
        .unwrap();

    if let Some(remote_addr) = remote_addr {
        request
            .extensions_mut()
            .insert(ConnectInfo::<SocketAddr>(remote_addr));
    }

    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json = serde_json::from_slice::<Value>(&body).unwrap();
    (status, json)
}

fn assert_enveloped(json: &Value) {
    let object = json.as_object().expect("response must be object");
    assert!(object.contains_key("meta"));
    assert!(object.contains_key("data") || object.contains_key("error"));
}

#[tokio::test]
async fn router_fallbacks_use_envelope() {
    let app = test_app();

    for (method, path, status) in [
        (Method::GET, "/missing", StatusCode::NOT_FOUND),
        (
            Method::GET,
            "/v1/auth/signup",
            StatusCode::METHOD_NOT_ALLOWED,
        ),
    ] {
        let (actual_status, json) =
            send(&app, method, path, None, &[], None).await;
        assert_eq!(actual_status, status);
        assert_enveloped(&json);
        assert!(json.get("error").is_some());
    }
}

#[tokio::test]
async fn public_json_routes_wrap_json_rejections() {
    let app = test_app();

    for (method, path) in [
        (Method::POST, "/v1/auth/signup"),
        (Method::POST, "/v1/auth/login"),
        (Method::POST, "/v1/auth/guest"),
        (Method::POST, "/v1/auth/email/verify"),
        (Method::POST, "/v1/auth/email/resend"),
        (Method::POST, "/v1/auth/password/forgot"),
        (Method::POST, "/v1/auth/password/reset"),
        (Method::POST, "/v1/auth/passkey/login/finish"),
    ] {
        let (status, json) = send(
            &app,
            method,
            path,
            Some("{"),
            &[("content-type", "application/json")],
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "route {path}");
        assert_enveloped(&json);
        assert!(json.get("error").is_some(), "route {path}");
    }
}

#[tokio::test]
async fn protected_auth_routes_wrap_unauthorized_errors() {
    let app = test_app();

    let cases = [
        (Method::POST, "/v1/auth/logout", None),
        (Method::GET, "/v1/auth/me", None),
        (Method::PATCH, "/v1/auth/me", Some("{}")),
        (Method::POST, "/v1/auth/mfa/totp/enroll", None),
        (Method::PUT, "/v1/auth/mfa/totp/enroll", Some("{}")),
        (Method::POST, "/v1/auth/mfa/totp/verify", Some("{}")),
        (
            Method::POST,
            "/v1/auth/mfa/totp/recovery-codes/regenerate",
            Some("{}"),
        ),
        (Method::POST, "/v1/auth/session/revoke", Some("{}")),
        (Method::POST, "/v1/auth/session/revoke-all", None),
        (Method::PATCH, "/v1/auth/guest/email", Some("{}")),
        (Method::POST, "/v1/auth/guest/convert", Some("{}")),
        (Method::POST, "/v1/auth/password/change", Some("{}")),
        (Method::POST, "/v1/auth/passkey/register/start", None),
        (Method::POST, "/v1/auth/passkey/register/finish", Some("{}")),
        (Method::POST, "/v1/auth/passkey/login/start", None),
    ];

    for (method, path, body) in cases {
        let mut headers = Vec::new();
        if body.is_some() {
            headers.push(("content-type", "application/json"));
        }
        let (status, json) =
            send(&app, method, path, body, &headers, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "route {path}");
        assert_enveloped(&json);
        assert!(json.get("error").is_some(), "route {path}");
    }
}

#[tokio::test]
async fn internal_routes_wrap_success_forbidden_and_json_errors() {
    let app = test_app();
    let ok_jwt = internal_jwt(&[
        "admin:read:system",
        "session:validate:token",
        "admin:read:user",
    ]);
    let user_only_jwt = internal_jwt(&["admin:read:user"]);

    let (status, json) = send(
        &app,
        Method::GET,
        "/v1/internal/health",
        None,
        &[("authorization", &format!("Bearer {ok_jwt}"))],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_enveloped(&json);
    assert!(json.get("data").is_some());

    let (status, json) = send(
        &app,
        Method::GET,
        "/v1/internal/users?page=1&per_page=50",
        None,
        &[("authorization", &format!("Bearer {ok_jwt}"))],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_enveloped(&json);
    assert!(json.get("data").is_some());

    let (status, json) = send(
        &app,
        Method::GET,
        "/v1/internal/health",
        None,
        &[("authorization", &format!("Bearer {user_only_jwt}"))],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_enveloped(&json);
    assert!(json.get("error").is_some());

    let (status, json) = send(
        &app,
        Method::POST,
        "/v1/internal/users/00000000-0000-0000-0000-000000000001/disable",
        None,
        &[("authorization", &format!("Bearer {user_only_jwt}"))],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_enveloped(&json);
    assert!(json.get("error").is_some());

    for path in [
        "/v1/internal/session/validate",
        "/v1/internal/user/lookup",
        "/v1/internal/user/lookup-by-email",
    ] {
        let (status, json) = send(
            &app,
            Method::POST,
            path,
            Some("{"),
            &[
                ("authorization", &format!("Bearer {ok_jwt}")),
                ("content-type", "application/json"),
            ],
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "route {path}");
        assert_enveloped(&json);
        assert!(json.get("error").is_some(), "route {path}");
    }

    let (status, json) = send(
        &app,
        Method::GET,
        "/v1/internal/users?page=nope",
        None,
        &[("authorization", &format!("Bearer {ok_jwt}"))],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_enveloped(&json);
    assert!(json.get("error").is_some());
}

#[tokio::test]
async fn internal_network_guard_enforces_cidrs() {
    let app = test_app_with_cidrs(&["100.64.0.0/10"]);
    let ok_jwt = internal_jwt(&["admin:read:system"]);

    let (status, json) = send(
        &app,
        Method::GET,
        "/v1/internal/health",
        None,
        &[("authorization", &format!("Bearer {ok_jwt}"))],
        Some("100.64.1.10:8081".parse().unwrap()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_enveloped(&json);
    assert!(json.get("data").is_some());

    let (status, json) = send(
        &app,
        Method::GET,
        "/v1/internal/health",
        None,
        &[("authorization", &format!("Bearer {ok_jwt}"))],
        Some("203.0.113.10:8081".parse().unwrap()),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_enveloped(&json);
    assert_eq!(json["error"]["message"], "IP not allowed");
}

#[tokio::test]
async fn internal_network_guard_allows_empty_cidr_list() {
    let app = test_app_with_cidrs(&[]);
    let ok_jwt = internal_jwt(&["admin:read:system"]);

    let (status, json) = send(
        &app,
        Method::GET,
        "/v1/internal/health",
        None,
        &[("authorization", &format!("Bearer {ok_jwt}"))],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_enveloped(&json);
}

#[tokio::test]
async fn internal_network_guard_prefers_first_x_forwarded_for_ip() {
    let app = test_app_with_cidrs(&["100.64.0.0/10"]);
    let ok_jwt = internal_jwt(&["admin:read:system"]);

    let (status, json) = send(
        &app,
        Method::GET,
        "/v1/internal/health",
        None,
        &[
            ("authorization", &format!("Bearer {ok_jwt}")),
            ("x-forwarded-for", "100.64.9.1, 203.0.113.8"),
        ],
        Some("203.0.113.10:8081".parse().unwrap()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_enveloped(&json);
}

#[tokio::test]
async fn internal_network_guard_rejects_malformed_x_forwarded_for() {
    let app = test_app_with_cidrs(&["100.64.0.0/10"]);
    let ok_jwt = internal_jwt(&["admin:read:system"]);

    let (status, json) = send(
        &app,
        Method::GET,
        "/v1/internal/health",
        None,
        &[
            ("authorization", &format!("Bearer {ok_jwt}")),
            ("x-forwarded-for", "not-an-ip"),
        ],
        Some("100.64.1.10:8081".parse().unwrap()),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_enveloped(&json);
    assert_eq!(json["error"]["message"], "invalid client IP");
}

const RSA_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC0A9uJCir7yaHM\nKmH8EvJIWZPCW2vBmBCNpHdg31ZaT/HVGYQIATjVlhS84FwwyyCGhJOxe84sRzY0\nFmb3m0CUo9ay67vzr/ncLcBXGxoGPBtzo5fcIg58McfOzCE5ULV3SnnwsgNQmSH0\nN0FtJxmIHEtd97agzxKVFb0+kus4/zCiaM9AeGCCT4jsVxKdecTu1l4PMy7lOhW1\neYq9SRFm0ja3yJMx3jZNRvmDjppVVIvNEWFXWM/ixPbKxXR8RqPYISS1lo073H9c\nGrIqyXhXwUNUm2i8L2+qC8WvGAuKyCeeNihN5UN/B+su6XXCs1XzXFpICU16ccmw\ns4Vx+h77AgMBAAECggEAMfImDcpH7c9eeH7D7AQ3u/I6qIDkD3VJFnus8bBVzb4D\nq6wmMXBhXAWFoHghrBoX3qrXLbXbmPZzKBWVIRsu2m7w6Xi1j+HiEgCRrrliyZsQ\nxM99mYLLgRLwzMRfbX8iskP0PF+vwsOSI6fXG9lu4JB1Ks/JmKmLjtjWxo9N+2R/\nV+Zu7Xx7OamadQeCoOYbP4UOa+YnnQ3GZ/U5d4fAHRgw6uL90wC2TSl3iIR8Wnm4\nR4Em4l4zDDJ8zbnF4//TRPkI48IbehwA0yadQSaPSRA7RVfWxMlviWyNgiW2+Lg2\nZh5PHY++HpGQSMscefoO4NRdxH1du0f1HuXVNbcbbQKBgQDf1WIAYzbcFJZ+lYNA\nUNGKlLNNzXvKhM6eMuDOLaScffZQL+aafrjIXKd/tU3N6p1IV0u9xlID7uyj+qgh\nroPe5rvQOEH69YQ521Qu5NgjzZJXpAcvRJgj4TtmIN9lZPouH5G6J5zNxOYYwR/0\n4XCFwSluM+r2qVrdVJL4WbFifQKBgQDN4m+3yIwlP18BY+n+Qu63yNORp5a46MQ5\n/z2T+5LdAnpZWwWvqNqq0zVyRhc51kh7UGpIqPrzXgarqR2Pp7P7ntO3S/o/Bj6p\nzCkiqVV5ELKtsXNJKcLWPkynZ0Mr0ZyDs1toZnSr5cQ2/Otvs+KGKGWOCr1+5ZB5\nHRrBmcaI1wKBgHne8dwqKP2NTB+iAnOrTVv5+OKcxhEPXHxwUUyRN3ZpcwpX+mQW\nKUAWirCTI8jBPF/eAARVDeTMWxYxbQfhwDVGRe5qIyqkMRlbXSunODPOQybqzWqk\nG341rSS/M0M+xqUEVVEZLlwvH+VMibzIXn7FHGy/Yehpb2rhGKCWHWn1AoGBAMdd\nq90FwGAZO4B3JhFm8w7Y07bJ2DP6gnm+5fw0soR9b8izUZBGLGka2ThtEvSYwdtX\nhXQS3d9of4Ee5FdFiA3yQQXP9uWswGVgI71CyFfRiZSUrxR78gXQkh3Q6sS115/Y\nwH0aKYSDnDu7MqkaQhKzb5PaZqFI31vIiS5MIGpFAoGBAMbbKA2C7eVMs7JuokDT\n+vlJU+m90y5Xtc9JsiBt8suJoSokhw1lx8rKIEQ/AHKBq0/dChihXGfMREdvqHUX\nZTSfQ2lRZMYHBor6zV8CCIQa5zGI6l7lZCsZwy2zmY3LsUFCgxG1GROdZlGhIfFu\nOthpzeUl0+8iqB1j6SGr3JU6\n-----END PRIVATE KEY-----\n";
const RSA_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtAPbiQoq+8mhzCph/BLy\nSFmTwltrwZgQjaR3YN9WWk/x1RmECAE41ZYUvOBcMMsghoSTsXvOLEc2NBZm95tA\nlKPWsuu786/53C3AVxsaBjwbc6OX3CIOfDHHzswhOVC1d0p58LIDUJkh9DdBbScZ\niBxLXfe2oM8SlRW9PpLrOP8womjPQHhggk+I7FcSnXnE7tZeDzMu5ToVtXmKvUkR\nZtI2t8iTMd42TUb5g46aVVSLzRFhV1jP4sT2ysV0fEaj2CEktZaNO9x/XBqyKsl4\nV8FDVJtovC9vqgvFrxgLisgnnjYoTeVDfwfrLul1wrNV81xaSAlNenHJsLOFcfoe\n+wIDAQAB\n-----END PUBLIC KEY-----\n";
