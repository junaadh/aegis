use crate::secret::SecretString;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DatabaseConfig {
    pub url: String,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    #[serde(default = "default_min_idle")]
    pub min_idle: u32,
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_seconds: u64,
    #[serde(default)]
    pub encryption_key: Option<SecretString>,
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
