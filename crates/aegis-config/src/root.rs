use crate::{
    api::{ApiConfig, ApiConfigSrc},
    compliance::{ComplianceConfig, ComplianceConfigSrc},
    credentials::{CredentialsConfig, CredentialsConfigSrc},
    crypto::{CryptoConfig, CryptoConfigSrc},
    database::{DatabaseConfig, DatabaseConfigSrc},
    email::{EmailConfig, EmailConfigSrc},
    error::ConfigError,
    redis::{RedisConfig, RedisConfigSrc},
    ref_or::RefOr,
    secret::SecretString,
    server::{ServerConfig, ServerConfigSrc},
    session::{SessionConfig, SessionConfigSrc},
    webhooks::{WebhooksConfig, WebhooksConfigSrc},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub database: Option<DatabaseConfig>,
    #[serde(default)]
    pub redis: RedisConfig,
    #[serde(default)]
    pub session: Option<SessionConfig>,
    #[serde(default)]
    pub credentials: CredentialsConfig,
    #[serde(default)]
    pub email: EmailConfig,
    #[serde(default)]
    pub api: ApiConfig,
    #[serde(default)]
    pub crypto: CryptoConfig,
    #[serde(default)]
    pub compliance: ComplianceConfig,
    #[serde(default)]
    pub webhooks: WebhooksConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigSrc {
    #[serde(default)]
    pub server: ServerConfigSrc,
    #[serde(default)]
    pub database: Option<DatabaseConfigSrc>,
    #[serde(default)]
    pub redis: RedisConfigSrc,
    #[serde(default)]
    pub session: Option<SessionConfigSrc>,
    #[serde(default)]
    pub credentials: CredentialsConfigSrc,
    #[serde(default)]
    pub email: EmailConfigSrc,
    #[serde(default)]
    pub api: ApiConfigSrc,
    #[serde(default)]
    pub crypto: CryptoConfigSrc,
    #[serde(default)]
    pub compliance: ComplianceConfigSrc,
    #[serde(default)]
    pub webhooks: WebhooksConfigSrc,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            database: Some(DatabaseConfig {
                url: "postgresql://aegis:password@localhost:5432/aegis".to_owned(),
                ..DatabaseConfig::default()
            }),
            redis: RedisConfig::default(),
            session: Some(SessionConfig {
                secret: SecretString::new(""),
                ..SessionConfig::default()
            }),
            credentials: CredentialsConfig::default(),
            email: EmailConfig::default(),
            api: ApiConfig::default(),
            crypto: CryptoConfig::default(),
            compliance: ComplianceConfig::default(),
            webhooks: WebhooksConfig::default(),
        }
    }
}

impl Default for ConfigSrc {
    fn default() -> Self {
        Self {
            server: ServerConfigSrc::default(),
            database: Some(DatabaseConfigSrc {
                url: RefOr::Env("AEGIS_DATABASE_URL".to_owned()),
                ..DatabaseConfigSrc::default()
            }),
            redis: RedisConfigSrc::default(),
            session: Some(SessionConfigSrc {
                secret: RefOr::Env("AEGIS_SESSION_SECRET".to_owned()),
                ..SessionConfigSrc::default()
            }),
            credentials: CredentialsConfigSrc::default(),
            email: EmailConfigSrc::default(),
            api: ApiConfigSrc::default(),
            crypto: CryptoConfigSrc::default(),
            compliance: ComplianceConfigSrc::default(),
            webhooks: WebhooksConfigSrc::default(),
        }
    }
}

impl ConfigSrc {
    pub fn resolve(&self) -> Result<Config, ConfigError> {
        let database = self
            .database
            .as_ref()
            .map(|db| db.resolve())
            .transpose()?;

        let session = self
            .session
            .as_ref()
            .map(|s| s.resolve())
            .transpose()?;

        let config = Config {
            server: self.server.resolve()?,
            database,
            redis: self.redis.resolve()?,
            session,
            credentials: self.credentials.resolve()?,
            email: self.email.resolve()?,
            api: self.api.resolve()?,
            crypto: self.crypto.resolve()?,
            compliance: self.compliance.resolve()?,
            webhooks: self.webhooks.resolve()?,
        };

        config.validate()?;
        Ok(config)
    }
}

const DEFAULT_FILENAME: &str = "aegis.toml";

const DEFAULT_HEADER: &[&str] = &[
    "#:schema https://raw.githubusercontent.com/junaadh/aegis/schemas/config/v1.json",
    "",
    "# aegis.toml — Aegis Authentication & Identity Platform",
    "# Version: 1.0",
];

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigError> {
        let resolved = path.unwrap_or(Path::new(DEFAULT_FILENAME));
        Self::from_file(resolved)
    }

    pub fn from_toml(input: &str) -> Result<Self, ConfigError> {
        let source: ConfigSrc = toml::from_str(input)?;
        source.resolve()
    }

    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_toml(&contents)
    }

    pub fn to_toml(&self) -> Result<String, ConfigError> {
        let mut out = DEFAULT_HEADER.join("\n\n");
        out.push('\n');
        let body = toml::to_string_pretty(self)
            .map_err(|e| ConfigError::Serialize(e.to_string()))?;
        out.push_str(&body);
        Ok(out)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        self.server.validate().map_err(ConfigError::Validation)?;

        if let Some(ref db) = self.database {
            db.validate().map_err(ConfigError::Validation)?;
        } else {
            return Err(ConfigError::MissingField("database".to_owned()));
        }

        if let Some(ref session) = self.session {
            session.validate().map_err(ConfigError::Validation)?;
        } else {
            return Err(ConfigError::MissingField("session".to_owned()));
        }

        self.email.validate().map_err(ConfigError::Validation)?;

        Ok(())
    }
}

impl ConfigSrc {
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_toml(&contents)
    }

    pub fn from_toml(input: &str) -> Result<Self, ConfigError> {
        toml::from_str(input).map_err(ConfigError::from)
    }

    pub fn to_toml(&self) -> Result<String, ConfigError> {
        let mut out = DEFAULT_HEADER.join("\n\n");
        out.push('\n');
        let body = toml::to_string_pretty(self)
            .map_err(|e| ConfigError::Serialize(e.to_string()))?;
        out.push_str(&body);
        Ok(out)
    }
}
