use crate::enums::SameSite;
use crate::secret::SecretString;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionConfig {
    #[schemars(title = "Session secret", description = "Secret key for signing session tokens. Use env:VAR reference.")]
    pub secret: SecretString,

    #[schemars(title = "Max age", description = "Maximum session lifetime in hours.")]
    #[serde(default = "default_max_age_hours")]
    pub max_age_hours: u64,

    #[schemars(title = "Idle timeout", description = "Session idle timeout in minutes.")]
    #[serde(default = "default_idle_timeout_minutes")]
    pub idle_timeout_minutes: u64,

    #[serde(default)]
    pub cookie: CookieConfig,

    #[serde(default)]
    pub bearer: BearerConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CookieConfig {
    #[schemars(title = "Cookie name", description = "Name of the session cookie.")]
    #[serde(default = "default_cookie_name")]
    pub name: String,

    #[schemars(title = "Cookie path", description = "URL path for the cookie.")]
    #[serde(default = "default_cookie_path")]
    pub path: String,

    #[schemars(title = "Cookie domain", description = "Domain for the cookie.")]
    #[serde(default)]
    pub domain: Option<String>,

    #[schemars(title = "Secure", description = "Only send cookie over HTTPS.")]
    #[serde(default = "default_true")]
    pub secure: bool,

    #[schemars(title = "HTTP only", description = "Prevent JavaScript access to cookie.")]
    #[serde(default = "default_true")]
    pub http_only: bool,

    #[schemars(title = "SameSite", description = "Cookie SameSite policy.")]
    #[serde(default)]
    pub same_site: SameSite,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BearerConfig {
    #[schemars(title = "Token length", description = "Length of opaque bearer tokens in bytes.")]
    #[serde(default = "default_opaque_token_length")]
    pub opaque_token_length: u32,

    #[schemars(title = "Default TTL", description = "Default bearer token TTL in minutes.")]
    #[serde(default = "default_bearer_ttl")]
    pub default_ttl_minutes: u64,

    #[schemars(title = "Refresh tokens", description = "Enable refresh token flow.")]
    #[serde(default)]
    pub refresh_token_enabled: bool,

    #[schemars(title = "Refresh TTL", description = "Refresh token TTL in days.")]
    #[serde(default = "default_refresh_ttl")]
    pub refresh_token_ttl_days: u64,
}

fn default_true() -> bool {
    true
}

fn default_max_age_hours() -> u64 {
    168
}

fn default_idle_timeout_minutes() -> u64 {
    30
}

fn default_cookie_name() -> String {
    "aegis_session".to_owned()
}

fn default_cookie_path() -> String {
    "/".to_owned()
}

fn default_opaque_token_length() -> u32 {
    32
}

fn default_bearer_ttl() -> u64 {
    15
}

fn default_refresh_ttl() -> u64 {
    30
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            secret: SecretString::new(String::new()),
            max_age_hours: default_max_age_hours(),
            idle_timeout_minutes: default_idle_timeout_minutes(),
            cookie: CookieConfig::default(),
            bearer: BearerConfig::default(),
        }
    }
}

impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            name: default_cookie_name(),
            path: default_cookie_path(),
            domain: None,
            secure: default_true(),
            http_only: default_true(),
            same_site: SameSite::default(),
        }
    }
}

impl Default for BearerConfig {
    fn default() -> Self {
        Self {
            opaque_token_length: default_opaque_token_length(),
            default_ttl_minutes: default_bearer_ttl(),
            refresh_token_enabled: false,
            refresh_token_ttl_days: default_refresh_ttl(),
        }
    }
}

impl SessionConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.secret.raw().is_empty() {
            return Err("session.secret is required".to_owned());
        }
        if self.max_age_hours == 0 {
            return Err("session.max_age_hours must be > 0".to_owned());
        }
        Ok(())
    }
}
