use crate::{
    api::ApiConfig, compliance::ComplianceConfig, credentials::CredentialsConfig,
    crypto::CryptoConfig, database::DatabaseConfig, email::EmailConfig, error::ConfigError,
    redis::RedisConfig, secret::SecretString, server::ServerConfig, session::SessionConfig,
    webhooks::WebhooksConfig,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
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
                secret: SecretString::from_env("AEGIS_SESSION_SECRET"),
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

const DEFAULT_FILENAME: &str = "aegis.toml";

const DEFAULT_HEADER: &[&str] = &[
    "# aegis.toml — Aegis Authentication & Identity Platform",
    "# Version: 1.0",
    "# Schema: https://raw.githubusercontent.com/junaadh/aegis/schemas/config/v1.json",
];

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigError> {
        let resolved = path.unwrap_or(Path::new(DEFAULT_FILENAME));
        Self::from_file(resolved)
    }

    pub fn from_toml(input: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(input)?;
        config.validate()?;
        Ok(config)
    }

    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_toml(&contents)
    }

    pub fn to_toml(&self) -> Result<String, ConfigError> {
        let mut out = DEFAULT_HEADER.join("\n");
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
