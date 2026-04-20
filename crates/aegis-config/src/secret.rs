use schemars::schema::{Schema, SchemaObject, SingleOrVec};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretString(String);

impl JsonSchema for SecretString {
    fn schema_name() -> String {
        "SecretString".to_owned()
    }

    fn json_schema(_: &mut schemars::r#gen::SchemaGenerator) -> Schema {
        Schema::Object(SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(
                schemars::schema::InstanceType::String,
            ))),
            ..Default::default()
        })
    }

    fn is_referenceable() -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretError {
    EnvVarMissing(String),
    FileRead { path: String, source: String },
    InvalidReference(String),
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EnvVarMissing(var) => write!(f, "environment variable not found: {var}"),
            Self::FileRead { path, source } => {
                write!(f, "failed to read file '{path}': {source}")
            }
            Self::InvalidReference(msg) => write!(f, "invalid secret reference: {msg}"),
        }
    }
}

impl std::error::Error for SecretError {}

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn from_env(var_name: impl AsRef<str>) -> Self {
        Self(format!("env:{}", var_name.as_ref()))
    }

    pub fn from_file(path: impl AsRef<str>) -> Self {
        Self(format!("file:{}", path.as_ref()))
    }

    pub fn raw(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    pub fn resolve(&self) -> Result<String, SecretError> {
        if let Some(var) = self.0.strip_prefix("env:") {
            std::env::var(var).map_err(|_| SecretError::EnvVarMissing(var.to_owned()))
        } else if let Some(path) = self.0.strip_prefix("file:") {
            std::fs::read_to_string(path).map_err(|e| SecretError::FileRead {
                path: path.to_owned(),
                source: e.to_string(),
            })
        } else {
            Ok(self.0.clone())
        }
    }

    pub fn is_reference(&self) -> bool {
        self.0.starts_with("env:") || self.0.starts_with("file:")
    }

    pub fn is_env_ref(&self) -> bool {
        self.0.starts_with("env:")
    }

    pub fn is_file_ref(&self) -> bool {
        self.0.starts_with("file:")
    }

    pub fn env_var_name(&self) -> Option<&str> {
        self.0.strip_prefix("env:")
    }

    pub fn file_path(&self) -> Option<&str> {
        self.0.strip_prefix("file:")
    }
}

impl Serialize for SecretString {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(Self(s))
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_env_ref() {
            f.write_str("***")?;
        } else {
            f.write_str(&self.0)?;
        }
        Ok(())
    }
}
