use crate::enums::SameSite;
use crate::error::ConfigError;
use crate::ref_or::RefOr;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionConfig {
    #[schemars(
        title = "Session secret",
        description = "Secret key for signing session tokens. Use env:VAR reference."
    )]
    pub secret: String,

    #[schemars(
        title = "Max age",
        description = "Maximum session lifetime in hours."
    )]
    #[serde(default = "default_max_age_hours")]
    pub max_age_hours: u64,

    #[schemars(
        title = "Idle timeout",
        description = "Session idle timeout in minutes."
    )]
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
    #[schemars(
        title = "Cookie name",
        description = "Name of the session cookie."
    )]
    #[serde(default = "default_cookie_name")]
    pub name: String,

    #[schemars(
        title = "Cookie path",
        description = "URL path for the cookie."
    )]
    #[serde(default = "default_cookie_path")]
    pub path: String,

    #[schemars(
        title = "Cookie domain",
        description = "Domain for the cookie."
    )]
    #[serde(default)]
    pub domain: Option<String>,

    #[schemars(title = "Secure", description = "Only send cookie over HTTPS.")]
    #[serde(default = "default_true")]
    pub secure: bool,

    #[schemars(
        title = "HTTP only",
        description = "Prevent JavaScript access to cookie."
    )]
    #[serde(default = "default_true")]
    pub http_only: bool,

    #[schemars(title = "SameSite", description = "Cookie SameSite policy.")]
    #[serde(default)]
    pub same_site: SameSite,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BearerConfig {
    #[schemars(
        title = "Token length",
        description = "Length of opaque bearer tokens in bytes."
    )]
    #[serde(default = "default_opaque_token_length")]
    pub opaque_token_length: u32,

    #[schemars(
        title = "Default TTL",
        description = "Default bearer token TTL in minutes."
    )]
    #[serde(default = "default_bearer_ttl")]
    pub default_ttl_minutes: u64,

    #[schemars(
        title = "Refresh tokens",
        description = "Enable refresh token flow."
    )]
    #[serde(default)]
    pub refresh_token_enabled: bool,

    #[schemars(
        title = "Refresh TTL",
        description = "Refresh token TTL in days."
    )]
    #[serde(default = "default_refresh_ttl")]
    pub refresh_token_ttl_days: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionConfigSrc {
    #[schemars(
        title = "Session secret",
        description = "Secret key for signing session tokens. Use env:VAR reference."
    )]
    pub secret: RefOr<String>,

    #[schemars(
        title = "Max age",
        description = "Maximum session lifetime in hours."
    )]
    #[serde(default = "default_max_age_hours_or")]
    pub max_age_hours: RefOr<u64>,

    #[schemars(
        title = "Idle timeout",
        description = "Session idle timeout in minutes."
    )]
    #[serde(default = "default_idle_timeout_minutes_or")]
    pub idle_timeout_minutes: RefOr<u64>,

    #[serde(default)]
    pub cookie: RefOr<CookieConfigSrc>,

    #[serde(default)]
    pub bearer: RefOr<BearerConfigSrc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CookieConfigSrc {
    #[schemars(
        title = "Cookie name",
        description = "Name of the session cookie."
    )]
    #[serde(default = "default_cookie_name_or")]
    pub name: RefOr<String>,

    #[schemars(
        title = "Cookie path",
        description = "URL path for the cookie."
    )]
    #[serde(default = "default_cookie_path_or")]
    pub path: RefOr<String>,

    #[schemars(
        title = "Cookie domain",
        description = "Domain for the cookie."
    )]
    #[serde(default)]
    pub domain: RefOr<Option<String>>,

    #[schemars(title = "Secure", description = "Only send cookie over HTTPS.")]
    #[serde(default = "default_true_or")]
    pub secure: RefOr<bool>,

    #[schemars(
        title = "HTTP only",
        description = "Prevent JavaScript access to cookie."
    )]
    #[serde(default = "default_true_or")]
    pub http_only: RefOr<bool>,

    #[schemars(title = "SameSite", description = "Cookie SameSite policy.")]
    #[serde(default)]
    pub same_site: RefOr<SameSite>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BearerConfigSrc {
    #[schemars(
        title = "Token length",
        description = "Length of opaque bearer tokens in bytes."
    )]
    #[serde(default = "default_opaque_token_length_or")]
    pub opaque_token_length: RefOr<u32>,

    #[schemars(
        title = "Default TTL",
        description = "Default bearer token TTL in minutes."
    )]
    #[serde(default = "default_bearer_ttl_or")]
    pub default_ttl_minutes: RefOr<u64>,

    #[schemars(
        title = "Refresh tokens",
        description = "Enable refresh token flow."
    )]
    #[serde(default = "default_false_or")]
    pub refresh_token_enabled: RefOr<bool>,

    #[schemars(
        title = "Refresh TTL",
        description = "Refresh token TTL in days."
    )]
    #[serde(default = "default_refresh_ttl_or")]
    pub refresh_token_ttl_days: RefOr<u64>,
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

fn default_true_or() -> RefOr<bool> {
    RefOr::Value(true)
}

fn default_false_or() -> RefOr<bool> {
    RefOr::Value(false)
}

fn default_max_age_hours_or() -> RefOr<u64> {
    RefOr::Value(default_max_age_hours())
}

fn default_idle_timeout_minutes_or() -> RefOr<u64> {
    RefOr::Value(default_idle_timeout_minutes())
}

fn default_cookie_name_or() -> RefOr<String> {
    RefOr::Value(default_cookie_name())
}

fn default_cookie_path_or() -> RefOr<String> {
    RefOr::Value(default_cookie_path())
}

fn default_opaque_token_length_or() -> RefOr<u32> {
    RefOr::Value(default_opaque_token_length())
}

fn default_bearer_ttl_or() -> RefOr<u64> {
    RefOr::Value(default_bearer_ttl())
}

fn default_refresh_ttl_or() -> RefOr<u64> {
    RefOr::Value(default_refresh_ttl())
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            secret: String::new(),
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

impl Default for SessionConfigSrc {
    fn default() -> Self {
        Self {
            secret: RefOr::Value(String::new()),
            max_age_hours: default_max_age_hours_or(),
            idle_timeout_minutes: default_idle_timeout_minutes_or(),
            cookie: RefOr::default(),
            bearer: RefOr::default(),
        }
    }
}

impl Default for CookieConfigSrc {
    fn default() -> Self {
        Self {
            name: default_cookie_name_or(),
            path: default_cookie_path_or(),
            domain: RefOr::Value(None),
            secure: default_true_or(),
            http_only: default_true_or(),
            same_site: RefOr::default(),
        }
    }
}

impl Default for BearerConfigSrc {
    fn default() -> Self {
        Self {
            opaque_token_length: default_opaque_token_length_or(),
            default_ttl_minutes: default_bearer_ttl_or(),
            refresh_token_enabled: default_false_or(),
            refresh_token_ttl_days: default_refresh_ttl_or(),
        }
    }
}

impl SessionConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.secret.is_empty() {
            return Err("session.secret is required".to_owned());
        }
        if self.max_age_hours == 0 {
            return Err("session.max_age_hours must be > 0".to_owned());
        }
        Ok(())
    }
}

impl SessionConfigSrc {
    pub fn resolve(&self) -> Result<SessionConfig, ConfigError> {
        let secret = self.secret.resolve()?;
        let max_age_hours = self.max_age_hours.resolve()?;
        let idle_timeout_minutes = self.idle_timeout_minutes.resolve()?;
        let cookie = self.cookie.resolve_nested(|s| s.resolve())?;
        let bearer = self.bearer.resolve_nested(|s| s.resolve())?;
        let config = SessionConfig {
            secret,
            max_age_hours,
            idle_timeout_minutes,
            cookie,
            bearer,
        };
        config.validate().map_err(ConfigError::Validation)?;
        Ok(config)
    }
}

impl CookieConfigSrc {
    pub fn resolve(&self) -> Result<CookieConfig, ConfigError> {
        Ok(CookieConfig {
            name: self.name.resolve()?,
            path: self.path.resolve()?,
            domain: self.domain.resolve()?,
            secure: self.secure.resolve()?,
            http_only: self.http_only.resolve()?,
            same_site: self.same_site.resolve()?,
        })
    }
}

impl BearerConfigSrc {
    pub fn resolve(&self) -> Result<BearerConfig, ConfigError> {
        Ok(BearerConfig {
            opaque_token_length: self.opaque_token_length.resolve()?,
            default_ttl_minutes: self.default_ttl_minutes.resolve()?,
            refresh_token_enabled: self.refresh_token_enabled.resolve()?,
            refresh_token_ttl_days: self.refresh_token_ttl_days.resolve()?,
        })
    }
}
