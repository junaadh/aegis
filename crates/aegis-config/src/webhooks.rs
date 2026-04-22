use crate::error::ConfigError;
use crate::ref_or::RefOr;
use crate::secret::SecretString;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct WebhooksConfig {
    #[schemars(title = "Enabled", description = "Enable outbound webhook delivery.")]
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

    #[schemars(title = "Events", description = "List of event types to subscribe to.")]
    #[serde(default)]
    pub events: Vec<String>,

    #[schemars(title = "Signing secret", description = "Secret for webhook payload signing. Use env:VAR reference.")]
    #[serde(default)]
    pub secret: Option<SecretString>,

    #[schemars(title = "Timeout", description = "Request timeout in seconds.")]
    #[serde(default = "default_webhook_timeout")]
    pub timeout_seconds: u64,

    #[schemars(title = "Max retries", description = "Maximum retry attempts for failed deliveries.")]
    #[serde(default = "default_webhook_retry")]
    pub retry_max_attempts: u32,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebhooksConfigSrc {
    #[schemars(title = "Enabled", description = "Enable outbound webhook delivery.")]
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub endpoints: Vec<WebhookEndpointConfigSrc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebhookEndpointConfigSrc {
    #[schemars(title = "URL", description = "Webhook endpoint URL.")]
    pub url: String,

    #[schemars(title = "Events", description = "List of event types to subscribe to.")]
    #[serde(default)]
    pub events: Vec<String>,

    #[schemars(title = "Signing secret", description = "Secret for webhook payload signing. Use env:VAR reference.")]
    #[serde(default)]
    pub secret: Option<RefOr<SecretString>>,

    #[schemars(title = "Timeout", description = "Request timeout in seconds.")]
    #[serde(default = "default_webhook_timeout")]
    pub timeout_seconds: u64,

    #[schemars(title = "Max retries", description = "Maximum retry attempts for failed deliveries.")]
    #[serde(default = "default_webhook_retry")]
    pub retry_max_attempts: u32,
}

fn default_webhook_timeout() -> u64 {
    10
}

fn default_webhook_retry() -> u32 {
    5
}

impl Default for WebhookEndpointConfigSrc {
    fn default() -> Self {
        Self {
            url: String::new(),
            events: Vec::new(),
            secret: None,
            timeout_seconds: default_webhook_timeout(),
            retry_max_attempts: default_webhook_retry(),
        }
    }
}

impl WebhooksConfigSrc {
    pub fn resolve(&self) -> Result<WebhooksConfig, ConfigError> {
        let mut endpoints = Vec::with_capacity(self.endpoints.len());
        for ep in &self.endpoints {
            endpoints.push(ep.resolve()?);
        }
        Ok(WebhooksConfig {
            enabled: self.enabled,
            endpoints,
        })
    }
}

impl WebhookEndpointConfigSrc {
    pub fn resolve(&self) -> Result<WebhookEndpointConfig, ConfigError> {
        let secret = match &self.secret {
            Some(ref_or) => Some(ref_or.resolve()?),
            None => None,
        };
        Ok(WebhookEndpointConfig {
            url: self.url.clone(),
            events: self.events.clone(),
            secret,
            timeout_seconds: self.timeout_seconds,
            retry_max_attempts: self.retry_max_attempts,
        })
    }
}
