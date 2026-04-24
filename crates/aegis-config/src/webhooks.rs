use crate::error::ConfigError;
use crate::ref_or::RefOr;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default,
)]
#[serde(deny_unknown_fields)]
pub struct WebhooksConfig {
    #[schemars(
        title = "Enabled",
        description = "Enable outbound webhook delivery."
    )]
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub endpoints: Vec<WebhookEndpointConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebhookEndpointConfig {
    #[schemars(title = "URL", description = "Webhook endpoint URL.")]
    pub url: String,

    #[schemars(
        title = "Events",
        description = "List of event types to subscribe to."
    )]
    #[serde(default)]
    pub events: Vec<String>,

    #[schemars(
        title = "Signing secret",
        description = "Secret for webhook payload signing. Use env:VAR reference."
    )]
    #[serde(default)]
    pub secret: Option<String>,

    #[schemars(title = "Timeout", description = "Request timeout in seconds.")]
    #[serde(default = "default_webhook_timeout")]
    pub timeout_seconds: u64,

    #[schemars(
        title = "Max retries",
        description = "Maximum retry attempts for failed deliveries."
    )]
    #[serde(default = "default_webhook_retry")]
    pub retry_max_attempts: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebhooksConfigSrc {
    #[schemars(
        title = "Enabled",
        description = "Enable outbound webhook delivery."
    )]
    #[serde(default)]
    pub enabled: RefOr<bool>,

    #[serde(default)]
    pub endpoints: RefOr<Vec<WebhookEndpointConfigSrc>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebhookEndpointConfigSrc {
    #[schemars(title = "URL", description = "Webhook endpoint URL.")]
    #[serde(default)]
    pub url: RefOr<String>,

    #[schemars(
        title = "Events",
        description = "List of event types to subscribe to."
    )]
    #[serde(default)]
    pub events: RefOr<Vec<String>>,

    #[schemars(
        title = "Signing secret",
        description = "Secret for webhook payload signing. Use env:VAR reference."
    )]
    #[serde(default)]
    pub secret: RefOr<Option<String>>,

    #[schemars(title = "Timeout", description = "Request timeout in seconds.")]
    #[serde(default = "default_webhook_timeout_or")]
    pub timeout_seconds: RefOr<u64>,

    #[schemars(
        title = "Max retries",
        description = "Maximum retry attempts for failed deliveries."
    )]
    #[serde(default = "default_webhook_retry_or")]
    pub retry_max_attempts: RefOr<u32>,
}

fn default_webhook_timeout() -> u64 {
    10
}

fn default_webhook_retry() -> u32 {
    5
}

fn default_webhook_timeout_or() -> RefOr<u64> {
    RefOr::Value(default_webhook_timeout())
}

fn default_webhook_retry_or() -> RefOr<u32> {
    RefOr::Value(default_webhook_retry())
}

impl Default for WebhooksConfigSrc {
    fn default() -> Self {
        Self {
            enabled: RefOr::Value(false),
            endpoints: RefOr::Value(Vec::new()),
        }
    }
}

impl Default for WebhookEndpointConfigSrc {
    fn default() -> Self {
        Self {
            url: RefOr::Value(String::new()),
            events: RefOr::Value(Vec::new()),
            secret: RefOr::Value(None),
            timeout_seconds: default_webhook_timeout_or(),
            retry_max_attempts: default_webhook_retry_or(),
        }
    }
}

impl WebhooksConfigSrc {
    pub fn resolve(&self) -> Result<WebhooksConfig, ConfigError> {
        let endpoints = self.endpoints.resolve_nested(|v| {
            v.iter().map(|e| e.resolve()).collect::<Result<Vec<_>, _>>()
        })?;
        Ok(WebhooksConfig {
            enabled: self.enabled.resolve()?,
            endpoints,
        })
    }
}

impl WebhookEndpointConfigSrc {
    pub fn resolve(&self) -> Result<WebhookEndpointConfig, ConfigError> {
        Ok(WebhookEndpointConfig {
            url: self.url.resolve()?,
            events: self.events.resolve()?,
            secret: self.secret.resolve()?,
            timeout_seconds: self.timeout_seconds.resolve()?,
            retry_max_attempts: self.retry_max_attempts.resolve()?,
        })
    }
}
