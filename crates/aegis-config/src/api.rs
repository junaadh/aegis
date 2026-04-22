use crate::error::ConfigError;
use crate::ref_or::RefOr;
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
    pub api_token: Option<String>,

    #[schemars(title = "Allowed CIDRs", description = "Network ranges allowed for internal API access.")]
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApiConfigSrc {
    #[serde(default)]
    pub rate_limit: RefOr<RateLimitConfigSrc>,

    #[serde(default)]
    pub internal: RefOr<InternalApiConfigSrc>,

    #[schemars(title = "Allowed metadata keys", description = "Allowlist of metadata keys users can set.")]
    #[serde(default)]
    pub metadata_allowed_keys: RefOr<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfigSrc {
    #[schemars(title = "Enabled", description = "Enable rate limiting.")]
    #[serde(default = "default_true_or")]
    pub enabled: RefOr<bool>,

    #[schemars(title = "Requests per minute", description = "Maximum requests per minute per client.")]
    #[serde(default = "default_requests_per_minute_or")]
    pub requests_per_minute: RefOr<u32>,

    #[schemars(title = "Burst", description = "Burst capacity for rate limiter.")]
    #[serde(default = "default_burst_or")]
    pub burst: RefOr<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InternalApiConfigSrc {
    #[schemars(title = "API token", description = "Static token for service-to-service auth. Use env:VAR reference.")]
    #[serde(default)]
    pub api_token: RefOr<Option<String>>,

    #[schemars(title = "Allowed CIDRs", description = "Network ranges allowed for internal API access.")]
    #[serde(default)]
    pub allowed_cidrs: RefOr<Vec<String>>,
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

fn default_true_or() -> RefOr<bool> {
    RefOr::Value(true)
}

fn default_requests_per_minute_or() -> RefOr<u32> {
    RefOr::Value(60)
}

fn default_burst_or() -> RefOr<u32> {
    RefOr::Value(10)
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

impl Default for ApiConfigSrc {
    fn default() -> Self {
        Self {
            rate_limit: RefOr::Value(RateLimitConfigSrc::default()),
            internal: RefOr::Value(InternalApiConfigSrc::default()),
            metadata_allowed_keys: RefOr::Value(Vec::new()),
        }
    }
}

impl Default for RateLimitConfigSrc {
    fn default() -> Self {
        Self {
            enabled: default_true_or(),
            requests_per_minute: default_requests_per_minute_or(),
            burst: default_burst_or(),
        }
    }
}

impl Default for InternalApiConfigSrc {
    fn default() -> Self {
        Self {
            api_token: RefOr::Value(None),
            allowed_cidrs: RefOr::Value(Vec::new()),
        }
    }
}

impl ApiConfigSrc {
    pub fn resolve(&self) -> Result<ApiConfig, ConfigError> {
        Ok(ApiConfig {
            rate_limit: self.rate_limit.resolve_nested(|s| s.resolve())?,
            internal: self.internal.resolve_nested(|s| s.resolve())?,
            metadata_allowed_keys: self.metadata_allowed_keys.resolve()?,
        })
    }
}

impl RateLimitConfigSrc {
    pub fn resolve(&self) -> Result<RateLimitConfig, ConfigError> {
        Ok(RateLimitConfig {
            enabled: self.enabled.resolve()?,
            requests_per_minute: self.requests_per_minute.resolve()?,
            burst: self.burst.resolve()?,
        })
    }
}

impl InternalApiConfigSrc {
    pub fn resolve(&self) -> Result<InternalApiConfig, ConfigError> {
        Ok(InternalApiConfig {
            api_token: self.api_token.resolve()?,
            allowed_cidrs: self.allowed_cidrs.resolve()?,
        })
    }
}
