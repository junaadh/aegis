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
    pub server: RefOr<ServerConfigSrc>,
    #[serde(default)]
    pub database: RefOr<Option<DatabaseConfigSrc>>,
    #[serde(default)]
    pub redis: RefOr<RedisConfigSrc>,
    #[serde(default)]
    pub session: RefOr<Option<SessionConfigSrc>>,
    #[serde(default)]
    pub credentials: RefOr<CredentialsConfigSrc>,
    #[serde(default)]
    pub email: RefOr<EmailConfigSrc>,
    #[serde(default)]
    pub api: RefOr<ApiConfigSrc>,
    #[serde(default)]
    pub crypto: RefOr<CryptoConfigSrc>,
    #[serde(default)]
    pub compliance: RefOr<ComplianceConfigSrc>,
    #[serde(default)]
    pub webhooks: RefOr<WebhooksConfigSrc>,
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
                secret: String::new(),
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
            server: RefOr::Value(ServerConfigSrc::default()),
            database: RefOr::Value(Some(DatabaseConfigSrc {
                url: RefOr::Env("AEGIS_DATABASE_URL".to_owned()),
                ..DatabaseConfigSrc::default()
            })),
            redis: RefOr::Value(RedisConfigSrc::default()),
            session: RefOr::Value(Some(SessionConfigSrc {
                secret: RefOr::Env("AEGIS_SESSION_SECRET".to_owned()),
                ..SessionConfigSrc::default()
            })),
            credentials: RefOr::Value(CredentialsConfigSrc::default()),
            email: RefOr::Value(EmailConfigSrc::default()),
            api: RefOr::Value(ApiConfigSrc::default()),
            crypto: RefOr::Value(CryptoConfigSrc::default()),
            compliance: RefOr::Value(ComplianceConfigSrc::default()),
            webhooks: RefOr::Value(WebhooksConfigSrc::default()),
        }
    }
}

impl ConfigSrc {
    pub fn resolve(&self) -> Result<Config, ConfigError> {
        let database = self
            .database
            .resolve_nested(|opt| {
                opt.as_ref()
                    .map(|db| db.resolve())
                    .transpose()
            })?;

        let session = self
            .session
            .resolve_nested(|opt| {
                opt.as_ref()
                    .map(|s| s.resolve())
                    .transpose()
            })?;

        let config = Config {
            server: self.server.resolve_nested(|s| s.resolve())?,
            database,
            redis: self.redis.resolve_nested(|s| s.resolve())?,
            session,
            credentials: self.credentials.resolve_nested(|s| s.resolve())?,
            email: self.email.resolve_nested(|s| s.resolve())?,
            api: self.api.resolve_nested(|s| s.resolve())?,
            crypto: self.crypto.resolve_nested(|s| s.resolve())?,
            compliance: self.compliance.resolve_nested(|s| s.resolve())?,
            webhooks: self.webhooks.resolve_nested(|s| s.resolve())?,
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
