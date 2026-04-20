use crate::secret::SecretString;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SessionConfig {
    pub secret: SecretString,
    #[serde(default = "default_max_age_hours")]
    pub max_age_hours: u64,
    #[serde(default = "default_idle_timeout_minutes")]
    pub idle_timeout_minutes: u64,
    #[serde(default)]
    pub cookie: CookieConfig,
    #[serde(default)]
    pub bearer: BearerConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CookieConfig {
    #[serde(default = "default_cookie_name")]
    pub name: String,
    #[serde(default = "default_cookie_path")]
    pub path: String,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default = "default_true")]
    pub secure: bool,
    #[serde(default = "default_true")]
    pub http_only: bool,
    #[serde(default = "default_same_site")]
    pub same_site: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BearerConfig {
    #[serde(default = "default_opaque_token_length")]
    pub opaque_token_length: u32,
    #[serde(default = "default_bearer_ttl")]
    pub default_ttl_minutes: u64,
    #[serde(default)]
    pub refresh_token_enabled: bool,
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

fn default_same_site() -> String {
    "lax".to_owned()
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

impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            name: default_cookie_name(),
            path: default_cookie_path(),
            domain: None,
            secure: default_true(),
            http_only: default_true(),
            same_site: default_same_site(),
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

impl SessionConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.secret.raw().is_empty() {
            return Err("session.secret is required".to_owned());
        }
        if self.max_age_hours == 0 {
            return Err("session.max_age_hours must be > 0".to_owned());
        }
        if !["strict", "lax", "none"].contains(&self.cookie.same_site.as_str()) {
            return Err(format!("invalid same_site: {}", self.cookie.same_site));
        }
        Ok(())
    }
}
