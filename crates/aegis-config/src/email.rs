use crate::secret::SecretString;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmailConfig {
    #[schemars(title = "Enabled", description = "Enable email delivery.")]
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[schemars(title = "From address", description = "Sender email address.")]
    #[serde(default)]
    pub from_address: Option<String>,

    #[schemars(title = "From name", description = "Sender display name.")]
    #[serde(default)]
    pub from_name: Option<String>,

    #[serde(default)]
    pub smtp: SmtpConfig,

    #[serde(default)]
    pub templates: EmailTemplatesConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SmtpConfig {
    #[schemars(title = "SMTP host", description = "SMTP server hostname.")]
    #[serde(default)]
    pub host: Option<String>,

    #[schemars(title = "SMTP port", description = "SMTP server port.")]
    #[serde(default = "default_smtp_port")]
    pub port: u16,

    #[schemars(title = "Username", description = "SMTP authentication username.")]
    #[serde(default)]
    pub username: Option<String>,

    #[schemars(title = "Password", description = "SMTP authentication password. Use env:VAR reference.")]
    #[serde(default)]
    pub password: Option<SecretString>,

    #[schemars(title = "STARTTLS", description = "Enable STARTTLS.")]
    #[serde(default = "default_true")]
    pub starttls: bool,

    #[schemars(title = "Timeout", description = "SMTP connection timeout in seconds.")]
    #[serde(default = "default_smtp_timeout")]
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct EmailTemplatesConfig {
    #[schemars(title = "Verification template", description = "Path to email verification template.")]
    #[serde(default)]
    pub verification: Option<String>,

    #[schemars(title = "Password reset template", description = "Path to password reset template.")]
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
