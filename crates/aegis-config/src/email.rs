use crate::error::ConfigError;
use crate::ref_or::RefOr;
use crate::secret::SecretString;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmailConfig {
    #[schemars(title = "Enabled", description = "Enable email delivery.")]
    #[serde(default)]
    pub enabled: bool,

    #[schemars(title = "From address", description = "Sender email address.")]
    #[serde(default)]
    pub from_address: String,

    #[schemars(title = "From name", description = "Sender display name.")]
    #[serde(default)]
    pub from_name: String,

    #[schemars(title = "Verification token TTL (hours)", description = "How long email verification tokens remain valid.")]
    #[serde(default = "default_verification_token_ttl_hours")]
    pub verification_token_ttl_hours: u64,

    #[schemars(title = "Password reset token TTL (minutes)", description = "How long password reset tokens remain valid.")]
    #[serde(default = "default_password_reset_token_ttl_minutes")]
    pub password_reset_token_ttl_minutes: u64,

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
    pub host: String,

    #[schemars(title = "SMTP port", description = "SMTP server port.")]
    #[serde(default = "default_smtp_port")]
    pub port: u16,

    #[schemars(title = "Username", description = "SMTP authentication username.")]
    #[serde(default)]
    pub username: String,

    #[schemars(title = "Password", description = "SMTP authentication password. Use env:VAR reference.")]
    #[serde(default)]
    pub password: SecretString,

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
    pub verification: String,

    #[schemars(title = "Password reset template", description = "Path to password reset template.")]
    #[serde(default)]
    pub password_reset: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmailConfigSrc {
    #[schemars(title = "Enabled", description = "Enable email delivery.")]
    #[serde(default)]
    pub enabled: bool,

    #[schemars(title = "From address", description = "Sender email address.")]
    #[serde(default)]
    pub from_address: RefOr<String>,

    #[schemars(title = "From name", description = "Sender display name.")]
    #[serde(default)]
    pub from_name: String,

    #[schemars(title = "Verification token TTL (hours)", description = "How long email verification tokens remain valid.")]
    #[serde(default = "default_verification_token_ttl_hours")]
    pub verification_token_ttl_hours: u64,

    #[schemars(title = "Password reset token TTL (minutes)", description = "How long password reset tokens remain valid.")]
    #[serde(default = "default_password_reset_token_ttl_minutes")]
    pub password_reset_token_ttl_minutes: u64,

    #[serde(default)]
    pub smtp: SmtpConfigSrc,

    #[serde(default)]
    pub templates: EmailTemplatesConfigSrc,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SmtpConfigSrc {
    #[schemars(title = "SMTP host", description = "SMTP server hostname.")]
    #[serde(default)]
    pub host: RefOr<String>,

    #[schemars(title = "SMTP port", description = "SMTP server port.")]
    #[serde(default = "default_smtp_port")]
    pub port: u16,

    #[schemars(title = "Username", description = "SMTP authentication username.")]
    #[serde(default)]
    pub username: String,

    #[schemars(title = "Password", description = "SMTP authentication password. Use env:VAR reference.")]
    #[serde(default)]
    pub password: RefOr<SecretString>,

    #[schemars(title = "STARTTLS", description = "Enable STARTTLS.")]
    #[serde(default = "default_true")]
    pub starttls: bool,

    #[schemars(title = "Timeout", description = "SMTP connection timeout in seconds.")]
    #[serde(default = "default_smtp_timeout")]
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmailTemplatesConfigSrc {
    #[schemars(title = "Verification template", description = "Path to email verification template.")]
    #[serde(default)]
    pub verification: String,

    #[schemars(title = "Password reset template", description = "Path to password reset template.")]
    #[serde(default)]
    pub password_reset: String,
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

fn default_verification_token_ttl_hours() -> u64 {
    24
}

fn default_password_reset_token_ttl_minutes() -> u64 {
    60
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            from_address: String::new(),
            from_name: String::new(),
            verification_token_ttl_hours: default_verification_token_ttl_hours(),
            password_reset_token_ttl_minutes: default_password_reset_token_ttl_minutes(),
            smtp: SmtpConfig::default(),
            templates: EmailTemplatesConfig::default(),
        }
    }
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: default_smtp_port(),
            username: String::new(),
            password: SecretString::new(""),
            starttls: default_true(),
            timeout_seconds: default_smtp_timeout(),
        }
    }
}

impl Default for EmailConfigSrc {
    fn default() -> Self {
        Self {
            enabled: false,
            from_address: RefOr::Value(String::new()),
            from_name: String::new(),
            verification_token_ttl_hours: default_verification_token_ttl_hours(),
            password_reset_token_ttl_minutes: default_password_reset_token_ttl_minutes(),
            smtp: SmtpConfigSrc::default(),
            templates: EmailTemplatesConfigSrc::default(),
        }
    }
}

impl Default for SmtpConfigSrc {
    fn default() -> Self {
        Self {
            host: RefOr::Value(String::new()),
            port: default_smtp_port(),
            username: String::new(),
            password: RefOr::Value(SecretString::new("")),
            starttls: default_true(),
            timeout_seconds: default_smtp_timeout(),
        }
    }
}

impl EmailConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.enabled {
            if self.from_address.is_empty() {
                return Err("email.from_address is required when email is enabled".to_owned());
            }
            if self.smtp.host.is_empty() {
                return Err("email.smtp.host is required when email is enabled".to_owned());
            }
        }
        Ok(())
    }
}

impl EmailConfigSrc {
    pub fn validate(&self) -> Result<(), String> {
        if self.enabled {
            match &self.from_address {
                RefOr::Value(v) if v.is_empty() => {
                    return Err("email.from_address is required when email is enabled".to_owned());
                }
                _ => {}
            }
            match &self.smtp.host {
                RefOr::Value(v) if v.is_empty() => {
                    return Err("email.smtp.host is required when email is enabled".to_owned());
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn resolve(&self) -> Result<EmailConfig, ConfigError> {
        let from_address = self.from_address.resolve()?;
        let smtp = self.smtp.resolve()?;
        let templates = self.templates.resolve()?;
        let config = EmailConfig {
            enabled: self.enabled,
            from_address,
            from_name: self.from_name.clone(),
            verification_token_ttl_hours: self.verification_token_ttl_hours,
            password_reset_token_ttl_minutes: self.password_reset_token_ttl_minutes,
            smtp,
            templates,
        };
        config.validate().map_err(ConfigError::Validation)?;
        Ok(config)
    }
}

impl SmtpConfigSrc {
    pub fn resolve(&self) -> Result<SmtpConfig, ConfigError> {
        Ok(SmtpConfig {
            host: self.host.resolve()?,
            port: self.port,
            username: self.username.clone(),
            password: self.password.resolve()?,
            starttls: self.starttls,
            timeout_seconds: self.timeout_seconds,
        })
    }
}

impl EmailTemplatesConfigSrc {
    pub fn resolve(&self) -> Result<EmailTemplatesConfig, ConfigError> {
        Ok(EmailTemplatesConfig {
            verification: self.verification.clone(),
            password_reset: self.password_reset.clone(),
        })
    }
}
