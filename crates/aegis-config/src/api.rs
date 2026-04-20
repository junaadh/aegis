use crate::secret::SecretString;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct ApiConfig {
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub internal: InternalApiConfig,
    #[serde(default)]
    pub metadata_allowed_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RateLimitConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_requests_per_minute")]
    pub requests_per_minute: u32,
    #[serde(default = "default_burst")]
    pub burst: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct InternalApiConfig {
    #[serde(default)]
    pub api_token: Option<SecretString>,
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,
}

fn default_true() -> bool {
    true
}

fn default_requests_per_minute() -> u32 {
    60
}

fn default_burst() -> u32 {
    10
}


impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_minute: default_requests_per_minute(),
            burst: default_burst(),
        }
    }
}


