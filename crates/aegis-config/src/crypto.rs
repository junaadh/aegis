use crate::enums::JwtAlgorithm;
use crate::secret::SecretString;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct CryptoConfig {
    #[schemars(title = "Master key", description = "Master encryption key. Use env:VAR or file:/path reference.")]
    #[serde(default)]
    pub master_key: Option<SecretString>,

    #[serde(default)]
    pub jwt: JwtConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct JwtConfig {
    #[schemars(title = "Enabled", description = "Enable JWT-based stateless authentication.")]
    #[serde(default)]
    pub enabled: bool,

    #[schemars(title = "Algorithm", description = "JWT signing algorithm.")]
    #[serde(default)]
    pub algorithm: JwtAlgorithm,

    #[schemars(title = "Private key", description = "Path or reference to JWT private key.")]
    #[serde(default)]
    pub private_key: Option<SecretString>,

    #[schemars(title = "Public key", description = "Path or reference to JWT public key.")]
    #[serde(default)]
    pub public_key: Option<SecretString>,

    #[schemars(title = "Issuer", description = "JWT issuer claim.")]
    #[serde(default)]
    pub issuer: Option<String>,

    #[schemars(title = "Audience", description = "JWT audience claim.")]
    #[serde(default)]
    pub audience: Option<String>,
}
