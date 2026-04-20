use crate::secret::SecretString;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct WebhooksConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub endpoints: Vec<WebhookEndpointConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WebhookEndpointConfig {
    pub url: String,
    #[serde(default)]
    pub events: Vec<String>,
    #[serde(default)]
    pub secret: Option<SecretString>,
    #[serde(default = "default_webhook_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_webhook_retry")]
    pub retry_max_attempts: u32,
}

fn default_webhook_timeout() -> u64 {
    10
}

fn default_webhook_retry() -> u32 {
    5
}


