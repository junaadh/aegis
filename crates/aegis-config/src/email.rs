use crate::secret::SecretString;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EmailConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub from_address: Option<String>,
    #[serde(default)]
    pub from_name: Option<String>,
    #[serde(default)]
    pub smtp: SmtpConfig,
    #[serde(default)]
    pub templates: EmailTemplatesConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SmtpConfig {
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default = "default_smtp_port")]
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<SecretString>,
    #[serde(default = "default_true")]
    pub starttls: bool,
    #[serde(default = "default_smtp_timeout")]
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct EmailTemplatesConfig {
    #[serde(default)]
    pub verification: Option<String>,
    #[serde(default)]
    pub password_reset: Option<String>,
}

fn default_true() -> bool {
    true
}

fn default_smtp_port() -> u16 {
    587
}

fn default_smtp_timeout() -> u64 {
    30
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            from_address: None,
            from_name: None,
            smtp: SmtpConfig::default(),
            templates: EmailTemplatesConfig::default(),
        }
    }
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            host: None,
            port: default_smtp_port(),
            username: None,
            password: None,
            starttls: default_true(),
            timeout_seconds: default_smtp_timeout(),
        }
    }
}


impl EmailConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.enabled {
            if self.from_address.as_ref().is_none_or(|s| s.is_empty()) {
                return Err("email.from_address is required when email is enabled".to_owned());
            }
            if self.smtp.host.as_ref().is_none_or(|s| s.is_empty()) {
                return Err("email.smtp.host is required when email is enabled".to_owned());
            }
        }
        Ok(())
    }
}
