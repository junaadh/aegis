use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RedisConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_redis_url")]
    pub url: String,
    #[serde(default = "default_redis_max_connections")]
    pub max_connections: u32,
}

fn default_redis_url() -> String {
    "redis://127.0.0.1:6379/0".to_owned()
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
