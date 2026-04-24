use std::env;
use std::fs::File;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use reqwest::cookie::{CookieStore, Jar};
use reqwest::{StatusCode, Url};
use serde_json::Value;
use sqlx::PgPool;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

pub const SERVER_URL: &str = "http://127.0.0.1:4001";
pub const COOKIE_NAME: &str = "aegis_session";

const TEST_CONFIG_NAME: &str = "aegis.integration.test.toml";

pub fn test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

pub fn required_env(name: &str, default: Option<&str>) -> String {
    env::var(name)
        .ok()
        .or_else(|| default.map(str::to_owned))
        .unwrap_or_else(|| panic!("{name} must be set"))
}

pub fn database_url() -> String {
    required_env(
        "AEGIS_DATABASE_URL",
        Some("postgres://aegis:aegis@localhost:5433/aegis_test"),
    )
}

pub fn redis_url() -> String {
    required_env("AEGIS_REDIS_URL", Some("redis://localhost:6380"))
}

pub fn smtp_host() -> String {
    required_env("AEGIS_EMAIL_SMTP_HOST", Some("localhost"))
}

pub fn smtp_port() -> u16 {
    required_env("AEGIS_EMAIL_SMTP_PORT", Some("1026"))
        .parse()
        .expect("SMTP port must be numeric")
}

pub fn internal_token() -> String {
    required_env("AEGIS_INTERNAL_TOKEN", Some("test-internal-token"))
}

pub fn mailpit_base_url() -> String {
    required_env("MAILPIT_WEB_URL", Some("http://localhost:8026"))
}

pub async fn pg_pool() -> PgPool {
    let pool = PgPool::connect(&database_url())
        .await
        .expect("connect postgres");
    aegis_migrate::MigrationRunner::new(pool.clone(), migrations_dir())
        .up()
        .await
        .expect("run migrations");
    pool
}

fn migrations_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../migrations")
}

pub async fn reset_db(pool: &PgPool) {
    sqlx::query(
        "TRUNCATE users, guests, sessions, password_credentials, passkey_credentials, totp_credentials, recovery_codes, roles, user_role_assignments, audit_logs, email_verification_tokens, password_reset_tokens, outbox RESTART IDENTITY CASCADE",
    )
    .execute(pool)
    .await
    .expect("truncate tables");
}

pub fn test_email(prefix: &str) -> String {
    format!("{prefix}-{}@example.test", uuid::Uuid::now_v7())
}

pub fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .expect("build reqwest client")
}

pub fn cookie_client() -> (reqwest::Client, std::sync::Arc<Jar>) {
    let jar = std::sync::Arc::new(Jar::default());
    let client = reqwest::Client::builder()
        .cookie_provider(jar.clone())
        .build()
        .expect("build cookie client");
    (client, jar)
}

pub fn extract_set_cookie(response: &reqwest::Response) -> Option<String> {
    response
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

pub fn session_cookie_value(jar: &Jar) -> Option<String> {
    let url = Url::parse(SERVER_URL).expect("valid server url");
    let cookies = jar.cookies(&url)?.to_str().ok()?.to_owned();
    for part in cookies.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix(&format!("{COOKIE_NAME}=")) {
            return Some(value.to_owned());
        }
    }
    None
}

pub fn assert_api_error_code(body: &Value, status: StatusCode, code: &str) {
    assert_eq!(
        body["error"]["code"], code,
        "unexpected error body for status {status}: {body}"
    );
    assert!(
        body["meta"]["requestId"].as_str().is_some(),
        "missing request id in error body: {body}"
    );
}

pub async fn create_test_config() -> PathBuf {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(TEST_CONFIG_NAME);
    let config = format!(
        r#"[server]
host = "127.0.0.1"
port = 4001
log_level = "debug"

[database]
url = "{database_url}"

[redis]
enabled = true
url = "{redis_url}"

[session]
secret = "{session_secret}"

[session.cookie]
name = "aegis_session"
path = "/"
secure = false
http_only = true
same_site = "lax"

[credentials.passkeys]
rp_id = "localhost"
rp_name = "Aegis Test"
origins = ["http://localhost:4001"]

[email]
enabled = true
from_address = "{from_address}"
from_name = "Aegis Test"

[email.smtp]
host = "{smtp_host}"
port = {smtp_port}
username = "{smtp_username}"
password = "{smtp_password}"
starttls = false

[api.internal]
api_token = "{internal_token}"
allowed_cidrs = []

[crypto]
master_key = "{master_key}"

[crypto.jwt]
enabled = false
"#,
        database_url = database_url(),
        redis_url = redis_url(),
        session_secret = required_env(
            "AEGIS_SESSION_SECRET",
            Some("test-session-secret-test-session-secret"),
        ),
        from_address = required_env(
            "AEGIS_EMAIL_FROM_ADDRESS",
            Some("noreply@aegis.test"),
        ),
        smtp_host = smtp_host(),
        smtp_port = smtp_port(),
        smtp_username = required_env("AEGIS_EMAIL_SMTP_USERNAME", Some("")),
        smtp_password = required_env("AEGIS_EMAIL_SMTP_PASSWORD", Some("")),
        internal_token = internal_token(),
        master_key = required_env(
            "AEGIS_CRYPTO_MASTER_KEY",
            Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ),
        ),
    );

    std::fs::write(&path, config).expect("write test config");
    path
}

pub async fn spawn_test_server() -> TestServer {
    let config_path = create_test_config().await;
    let bin_path = env!("CARGO_BIN_EXE_aegisd");
    let log_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target");
    std::fs::create_dir_all(&log_dir).expect("create test log dir");
    let log_path = log_dir.join(format!("{}.log", uuid::Uuid::now_v7()));
    let log_file = File::create(&log_path).expect("create test server log");
    let log_file_err = log_file.try_clone().expect("clone test server log");

    let child = Command::new(bin_path)
        .arg(&config_path)
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_file_err))
        .spawn()
        .expect("spawn aegisd");

    wait_for_health(Some(&log_path)).await;

    TestServer {
        child,
        config_path,
        log_path,
    }
}

pub struct TestServer {
    child: Child,
    config_path: PathBuf,
    log_path: PathBuf,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
        let _ = std::fs::remove_file(&self.config_path);
        let _ = std::fs::remove_file(&self.log_path);
    }
}

pub async fn wait_for_health(log_path: Option<&PathBuf>) {
    let client = http_client();
    let deadline = Instant::now() + Duration::from_secs(30);

    loop {
        let response = client
            .get(format!("{SERVER_URL}/v1/internal/health"))
            .bearer_auth(internal_token())
            .send()
            .await;

        if let Ok(response) = response
            && response.status().is_success()
        {
            return;
        }

        if Instant::now() >= deadline {
            let logs = log_path
                .and_then(|path| std::fs::read_to_string(path).ok())
                .unwrap_or_else(|| "<no logs available>".to_owned());
            panic!("timed out waiting for aegisd\n{logs}");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

pub async fn mailpit_messages() -> Value {
    http_client()
        .get(format!("{}/api/v1/messages", mailpit_base_url()))
        .send()
        .await
        .expect("fetch mailpit messages")
        .json::<Value>()
        .await
        .expect("parse mailpit messages")
}

fn object_contains_email(value: &Value, email: &str) -> bool {
    match value {
        Value::String(text) => text.contains(email),
        Value::Array(items) => {
            items.iter().any(|item| object_contains_email(item, email))
        }
        Value::Object(map) => {
            map.values().any(|item| object_contains_email(item, email))
        }
        _ => false,
    }
}

fn find_mailpit_snippet_for_email(
    value: &Value,
    email: &str,
) -> Option<String> {
    match value {
        Value::Object(map) => {
            if object_contains_email(value, email) {
                if let Some(snippet) =
                    map.get("Snippet").and_then(|snippet| snippet.as_str())
                {
                    return Some(snippet.to_owned());
                }
                if let Some(snippet) =
                    map.get("snippet").and_then(|snippet| snippet.as_str())
                {
                    return Some(snippet.to_owned());
                }
            }

            map.values()
                .find_map(|item| find_mailpit_snippet_for_email(item, email))
        }
        Value::Array(items) => items
            .iter()
            .find_map(|item| find_mailpit_snippet_for_email(item, email)),
        _ => None,
    }
}

pub async fn wait_for_mailpit_token(email: &str, marker: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(30);

    loop {
        let messages = mailpit_messages().await;
        if let Some(snippet) = find_mailpit_snippet_for_email(&messages, email)
            && let Some(token) = snippet.split(marker).nth(1)
        {
            let token = token.lines().next().unwrap_or_default().trim();
            if !token.is_empty() {
                return token.to_owned();
            }
        }

        assert!(
            Instant::now() < deadline,
            "timed out waiting for mailpit token"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

pub async fn signup(
    client: &reqwest::Client,
    email: &str,
    password: &str,
) -> reqwest::Response {
    client
        .post(format!("{SERVER_URL}/v1/auth/signup"))
        .json(&serde_json::json!({
            "email": email,
            "password": password,
            "displayName": "Integration User"
        }))
        .send()
        .await
        .expect("signup request")
}

pub async fn verify_email(token: &str) -> reqwest::Response {
    http_client()
        .post(format!("{SERVER_URL}/v1/auth/email/verify"))
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .expect("verify email request")
}

pub async fn login(
    client: &reqwest::Client,
    email: &str,
    password: &str,
) -> reqwest::Response {
    client
        .post(format!("{SERVER_URL}/v1/auth/login"))
        .json(&serde_json::json!({ "email": email, "password": password }))
        .send()
        .await
        .expect("login request")
}

pub async fn logout(client: &reqwest::Client) -> reqwest::Response {
    client
        .post(format!("{SERVER_URL}/v1/auth/logout"))
        .send()
        .await
        .expect("logout request")
}

pub async fn me(client: &reqwest::Client) -> reqwest::Response {
    client
        .get(format!("{SERVER_URL}/v1/auth/me"))
        .send()
        .await
        .expect("me request")
}

pub async fn validate_session(
    token: &str,
    auth_header: Option<&str>,
) -> reqwest::Response {
    let client = http_client();
    let mut request = client
        .post(format!("{SERVER_URL}/v1/internal/session/validate"))
        .json(&serde_json::json!({ "token": token }));

    if let Some(value) = auth_header {
        request = request.header(reqwest::header::AUTHORIZATION, value);
    }

    request.send().await.expect("validate session request")
}
