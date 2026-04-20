use crate::secret::SecretString;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct CryptoConfig {
    #[serde(default)]
    pub master_key: Option<SecretString>,
    #[serde(default)]
    pub jwt: JwtConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JwtConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_jwt_algorithm")]
    pub algorithm: String,
    #[serde(default)]
    pub private_key: Option<SecretString>,
    #[serde(default)]
    pub public_key: Option<SecretString>,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
}

fn default_jwt_algorithm() -> String {
    "RS256".to_owned()
}


impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            algorithm: default_jwt_algorithm(),
            private_key: None,
            public_key: None,
            issuer: None,
            audience: None,
        }
    }
}
