use crate::secret::SecretString;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct ApiConfig {
    #[serde(default)]
    pub rate_limit: RateLimitConfig,

    #[serde(default)]
    pub internal: InternalApiConfig,

    #[schemars(title = "Allowed metadata keys", description = "Allowlist of metadata keys users can set.")]
    #[serde(default)]
    pub metadata_allowed_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    #[schemars(title = "Enabled", description = "Enable rate limiting.")]
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[schemars(title = "Requests per minute", description = "Maximum requests per minute per client.")]
    #[serde(default = "default_requests_per_minute")]
    pub requests_per_minute: u32,

    #[schemars(title = "Burst", description = "Burst capacity for rate limiter.")]
    #[serde(default = "default_burst")]
    pub burst: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct InternalApiConfig {
    #[schemars(title = "API token", description = "Static token for service-to-service auth. Use env:VAR reference.")]
    #[serde(default)]
    pub api_token: Option<SecretString>,

    #[schemars(title = "Allowed CIDRs", description = "Network ranges allowed for internal API access.")]
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
