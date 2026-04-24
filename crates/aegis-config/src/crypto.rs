use crate::enums::JwtAlgorithm;
use crate::error::ConfigError;
use crate::ref_or::RefOr;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default,
)]
#[serde(deny_unknown_fields)]
pub struct CryptoConfig {
    #[schemars(
        title = "Master key",
        description = "Master encryption key. Use env:VAR or file:/path reference."
    )]
    #[serde(default)]
    pub master_key: Option<String>,

    #[serde(default)]
    pub jwt: JwtConfig,
}

#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default,
)]
#[serde(deny_unknown_fields)]
pub struct JwtConfig {
    #[schemars(
        title = "Enabled",
        description = "Enable JWT-based stateless authentication."
    )]
    #[serde(default)]
    pub enabled: bool,

    #[schemars(title = "Algorithm", description = "JWT signing algorithm.")]
    #[serde(default)]
    pub algorithm: JwtAlgorithm,

    #[schemars(
        title = "Private key",
        description = "Path or reference to JWT private key."
    )]
    #[serde(default)]
    pub private_key: Option<String>,

    #[schemars(
        title = "Public key",
        description = "Path or reference to JWT public key."
    )]
    #[serde(default)]
    pub public_key: Option<String>,

    #[schemars(title = "Issuer", description = "JWT issuer claim.")]
    #[serde(default)]
    pub issuer: Option<String>,

    #[schemars(title = "Audience", description = "JWT audience claim.")]
    #[serde(default)]
    pub audience: Option<String>,
}

#[derive(
    Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct CryptoConfigSrc {
    #[schemars(
        title = "Master key",
        description = "Master encryption key. Use env:VAR or file:/path reference."
    )]
    #[serde(default)]
    pub master_key: RefOr<Option<String>>,

    #[serde(default)]
    pub jwt: RefOr<JwtConfigSrc>,
}

impl CryptoConfigSrc {
    pub fn resolve(&self) -> Result<CryptoConfig, ConfigError> {
        Ok(CryptoConfig {
            master_key: self.master_key.resolve()?,
            jwt: self.jwt.resolve_nested(|s| s.resolve())?,
        })
    }
}

#[derive(
    Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct JwtConfigSrc {
    #[schemars(
        title = "Enabled",
        description = "Enable JWT-based stateless authentication."
    )]
    #[serde(default)]
    pub enabled: RefOr<bool>,

    #[schemars(title = "Algorithm", description = "JWT signing algorithm.")]
    #[serde(default)]
    pub algorithm: RefOr<JwtAlgorithm>,

    #[schemars(
        title = "Private key",
        description = "Path or reference to JWT private key."
    )]
    #[serde(default)]
    pub private_key: RefOr<Option<String>>,

    #[schemars(
        title = "Public key",
        description = "Path or reference to JWT public key."
    )]
    #[serde(default)]
    pub public_key: RefOr<Option<String>>,

    #[schemars(title = "Issuer", description = "JWT issuer claim.")]
    #[serde(default)]
    pub issuer: RefOr<Option<String>>,

    #[schemars(title = "Audience", description = "JWT audience claim.")]
    #[serde(default)]
    pub audience: RefOr<Option<String>>,
}

impl JwtConfigSrc {
    pub fn resolve(&self) -> Result<JwtConfig, ConfigError> {
        Ok(JwtConfig {
            enabled: self.enabled.resolve()?,
            algorithm: self.algorithm.resolve()?,
            private_key: self.private_key.resolve()?,
            public_key: self.public_key.resolve()?,
            issuer: self.issuer.resolve()?,
            audience: self.audience.resolve()?,
        })
    }
}

impl JwtConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }

        match self.algorithm {
            crate::JwtAlgorithm::RS256 | crate::JwtAlgorithm::ES256 => {}
            crate::JwtAlgorithm::HS256 => {
                return Err(ConfigError::Validation(
                    "crypto.jwt.algorithm must be RS256 or ES256 for internal service tokens"
                        .to_owned(),
                ));
            }
        }

        if self.private_key.as_deref().unwrap_or_default().is_empty() {
            return Err(ConfigError::MissingField(
                "crypto.jwt.private_key".to_owned(),
            ));
        }

        if self.public_key.as_deref().unwrap_or_default().is_empty() {
            return Err(ConfigError::MissingField(
                "crypto.jwt.public_key".to_owned(),
            ));
        }

        if self.issuer.as_deref().unwrap_or_default().is_empty() {
            return Err(ConfigError::MissingField(
                "crypto.jwt.issuer".to_owned(),
            ));
        }

        if self.audience.as_deref().unwrap_or_default().is_empty() {
            return Err(ConfigError::MissingField(
                "crypto.jwt.audience".to_owned(),
            ));
        }

        Ok(())
    }
}
