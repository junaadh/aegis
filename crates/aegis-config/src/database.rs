use crate::error::ConfigError;
use crate::ref_or::RefOr;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    #[schemars(
        title = "Database URL",
        description = "PostgreSQL connection string."
    )]
    pub url: String,

    #[schemars(
        title = "Max connections",
        description = "Maximum number of database connections."
    )]
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,

    #[schemars(
        title = "Min idle",
        description = "Minimum number of idle connections."
    )]
    #[serde(default = "default_min_idle")]
    pub min_idle: u32,

    #[schemars(
        title = "Connection timeout",
        description = "Connection timeout in seconds."
    )]
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_seconds: u64,

    #[schemars(
        title = "Encryption key",
        description = "Key for encrypting sensitive columns. Use env:VAR or file:/path references."
    )]
    #[serde(default)]
    pub encryption_key: Option<String>,
}

fn default_max_connections() -> u32 {
    25
}

fn default_min_idle() -> u32 {
    5
}

fn default_connection_timeout() -> u64 {
    30
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            max_connections: default_max_connections(),
            min_idle: default_min_idle(),
            connection_timeout_seconds: default_connection_timeout(),
            encryption_key: None,
        }
    }
}

impl DatabaseConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.url.is_empty() {
            return Err("database.url is required".to_owned());
        }
        if self.max_connections == 0 {
            return Err("database.max_connections must be > 0".to_owned());
        }
        Ok(())
    }
}

fn default_max_connections_or() -> RefOr<u32> {
    RefOr::Value(default_max_connections())
}

fn default_min_idle_or() -> RefOr<u32> {
    RefOr::Value(default_min_idle())
}

fn default_connection_timeout_or() -> RefOr<u64> {
    RefOr::Value(default_connection_timeout())
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfigSrc {
    #[schemars(
        title = "Database URL",
        description = "PostgreSQL connection string."
    )]
    #[serde(default)]
    pub url: RefOr<String>,

    #[schemars(
        title = "Max connections",
        description = "Maximum number of database connections."
    )]
    #[serde(default = "default_max_connections_or")]
    pub max_connections: RefOr<u32>,

    #[schemars(
        title = "Min idle",
        description = "Minimum number of idle connections."
    )]
    #[serde(default = "default_min_idle_or")]
    pub min_idle: RefOr<u32>,

    #[schemars(
        title = "Connection timeout",
        description = "Connection timeout in seconds."
    )]
    #[serde(default = "default_connection_timeout_or")]
    pub connection_timeout_seconds: RefOr<u64>,

    #[schemars(
        title = "Encryption key",
        description = "Key for encrypting sensitive columns. Use env:VAR or file:/path references."
    )]
    #[serde(default)]
    pub encryption_key: RefOr<Option<String>>,
}

impl Default for DatabaseConfigSrc {
    fn default() -> Self {
        Self {
            url: RefOr::Value(String::new()),
            max_connections: RefOr::Value(default_max_connections()),
            min_idle: RefOr::Value(default_min_idle()),
            connection_timeout_seconds: RefOr::Value(
                default_connection_timeout(),
            ),
            encryption_key: RefOr::Value(None),
        }
    }
}

impl DatabaseConfigSrc {
    pub fn resolve(&self) -> Result<DatabaseConfig, ConfigError> {
        Ok(DatabaseConfig {
            url: self.url.resolve()?,
            max_connections: self.max_connections.resolve()?,
            min_idle: self.min_idle.resolve()?,
            connection_timeout_seconds: self
                .connection_timeout_seconds
                .resolve()?,
            encryption_key: self.encryption_key.resolve()?,
        })
    }
}
