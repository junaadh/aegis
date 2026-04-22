use crate::error::ConfigError;
use crate::ref_or::RefOr;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RedisConfig {
    #[schemars(title = "Enabled", description = "Enable Redis for caching and rate limiting.")]
    #[serde(default)]
    pub enabled: bool,

    #[schemars(title = "Redis URL", description = "Redis connection string.")]
    #[serde(default = "default_redis_url")]
    pub url: String,

    #[schemars(title = "Max connections", description = "Maximum number of Redis connections.")]
    #[serde(default = "default_redis_max_connections")]
    pub max_connections: u32,
}

fn default_redis_url() -> String {
    "redis://127.0.0.1:6379/0".to_owned()
}

fn default_redis_url_ref() -> RefOr<String> {
    RefOr::Value(default_redis_url())
}

fn default_redis_max_connections() -> u32 {
    10
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: default_redis_url(),
            max_connections: default_redis_max_connections(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RedisConfigSrc {
    #[schemars(title = "Enabled", description = "Enable Redis for caching and rate limiting.")]
    #[serde(default)]
    pub enabled: bool,

    #[schemars(title = "Redis URL", description = "Redis connection string.")]
    #[serde(default = "default_redis_url_ref")]
    pub url: RefOr<String>,

    #[schemars(title = "Max connections", description = "Maximum number of Redis connections.")]
    #[serde(default = "default_redis_max_connections")]
    pub max_connections: u32,
}

impl Default for RedisConfigSrc {
    fn default() -> Self {
        Self {
            enabled: false,
            url: RefOr::Value(default_redis_url()),
            max_connections: default_redis_max_connections(),
        }
    }
}

impl RedisConfigSrc {
    pub fn resolve(&self) -> Result<RedisConfig, ConfigError> {
        Ok(RedisConfig {
            enabled: self.enabled,
            url: self.url.resolve()?,
            max_connections: self.max_connections,
        })
    }
}
