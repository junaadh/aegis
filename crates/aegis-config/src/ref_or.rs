use crate::error::ConfigError;
use schemars::schema::{
    InstanceType, Schema, SchemaObject, SingleOrVec, StringValidation, SubschemaValidation,
};
use schemars::JsonSchema;
use serde::de::IntoDeserializer;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefOr<T> {
    Value(T),
    Env(String),
    File(String),
}

impl<T: Default> Default for RefOr<T> {
    fn default() -> Self {
        RefOr::Value(T::default())
    }
}

impl<T> RefOr<T> {
    pub fn is_ref(&self) -> bool {
        !matches!(self, RefOr::Value(_))
    }

    pub fn env_var(&self) -> Option<&str> {
        match self {
            RefOr::Env(var) => Some(var),
            _ => None,
        }
    }
}

impl<T: Clone + ResolveLeaf> RefOr<T> {
    pub fn resolve(&self) -> Result<T, ConfigError> {
        match self {
            RefOr::Value(t) => Ok(t.clone()),
            RefOr::Env(var) => {
                let raw = std::env::var(var)
                    .map_err(|_| ConfigError::ResolveEnv { var: var.clone() })?;
                T::from_resolved_str(&raw)
            }
            RefOr::File(path) => {
                let raw = std::fs::read_to_string(path).map_err(|e| {
                    ConfigError::ResolveFile {
                        path: path.clone(),
                        source: e.to_string(),
                    }
                })?;
                T::from_resolved_str(raw.trim())
            }
        }
    }
}

impl<T: serde::de::DeserializeOwned> RefOr<T> {
    pub fn resolve_nested<R, F>(&self, f: F) -> Result<R, ConfigError>
    where
        F: FnOnce(&T) -> Result<R, ConfigError>,
    {
        match self {
            RefOr::Value(t) => f(t),
            RefOr::Env(var) => {
                let raw = std::env::var(var)
                    .map_err(|_| ConfigError::ResolveEnv { var: var.clone() })?;
                let src: T = toml::from_str(&raw)?;
                f(&src)
            }
            RefOr::File(path) => {
                let raw = std::fs::read_to_string(path).map_err(|e| {
                    ConfigError::ResolveFile {
                        path: path.clone(),
                        source: e.to_string(),
                    }
                })?;
                let src: T = toml::from_str(raw.trim())?;
                f(&src)
            }
        }
    }
}

impl<T: Serialize> Serialize for RefOr<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            RefOr::Value(t) => t.serialize(s),
            RefOr::Env(var) => format!("env:{var}").serialize(s),
            RefOr::File(path) => format!("file:{path}").serialize(s),
        }
    }
}

impl<'de, T: serde::de::DeserializeOwned> Deserialize<'de> for RefOr<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = toml::Value::deserialize(d)?;

        if let toml::Value::String(s) = &value {
            if let Some(var) = s.strip_prefix("env:") {
                return Ok(RefOr::Env(var.to_owned()));
            }
            if let Some(path) = s.strip_prefix("file:") {
                return Ok(RefOr::File(path.to_owned()));
            }
        }

        let t: T = T::deserialize(value.into_deserializer())
            .map_err(serde::de::Error::custom)?;
        Ok(RefOr::Value(t))
    }
}

impl<T: JsonSchema> JsonSchema for RefOr<T> {
    fn schema_name() -> String {
        format!("RefOr_{}", T::schema_name())
    }

    fn json_schema(r#gen: &mut schemars::r#gen::SchemaGenerator) -> Schema {
        let schemas = vec![
            T::json_schema(r#gen),
            Schema::Object(SchemaObject {
                instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::String))),
                string: Some(Box::new(StringValidation {
                    pattern: Some("^env:".to_owned()),
                    ..Default::default()
                })),
                ..Default::default()
            }),
            Schema::Object(SchemaObject {
                instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::String))),
                string: Some(Box::new(StringValidation {
                    pattern: Some("^file:".to_owned()),
                    ..Default::default()
                })),
                ..Default::default()
            }),
        ];

        Schema::Object(SchemaObject {
            subschemas: Some(Box::new(SubschemaValidation {
                any_of: Some(schemas),
                ..Default::default()
            })),
            ..Default::default()
        })
    }

    fn is_referenceable() -> bool {
        false
    }
}

pub trait ResolveLeaf: Sized {
    fn from_resolved_str(s: &str) -> Result<Self, ConfigError>;
}

fn parse_toml_scalar<T: serde::de::DeserializeOwned>(s: &str) -> Result<T, ConfigError> {
    let val = toml::Value::String(s.to_owned());
    T::deserialize(val.into_deserializer())
        .map_err(|e| ConfigError::Validation(format!("invalid value '{s}': {e}")))
}

impl ResolveLeaf for String {
    fn from_resolved_str(s: &str) -> Result<Self, ConfigError> {
        Ok(s.to_owned())
    }
}

impl ResolveLeaf for u16 {
    fn from_resolved_str(s: &str) -> Result<Self, ConfigError> {
        s.parse()
            .map_err(|_| ConfigError::Validation(format!("invalid u16: '{s}'")))
    }
}

impl ResolveLeaf for u32 {
    fn from_resolved_str(s: &str) -> Result<Self, ConfigError> {
        s.parse()
            .map_err(|_| ConfigError::Validation(format!("invalid u32: '{s}'")))
    }
}

impl ResolveLeaf for u64 {
    fn from_resolved_str(s: &str) -> Result<Self, ConfigError> {
        s.parse()
            .map_err(|_| ConfigError::Validation(format!("invalid u64: '{s}'")))
    }
}

impl ResolveLeaf for usize {
    fn from_resolved_str(s: &str) -> Result<Self, ConfigError> {
        s.parse()
            .map_err(|_| ConfigError::Validation(format!("invalid usize: '{s}'")))
    }
}

impl ResolveLeaf for bool {
    fn from_resolved_str(s: &str) -> Result<Self, ConfigError> {
        parse_toml_scalar(s)
    }
}

impl<T: ResolveLeaf> ResolveLeaf for Option<T> {
    fn from_resolved_str(s: &str) -> Result<Self, ConfigError> {
        if s.is_empty() {
            Ok(None)
        } else {
            T::from_resolved_str(s).map(Some)
        }
    }
}

impl ResolveLeaf for Vec<String> {
    fn from_resolved_str(_s: &str) -> Result<Self, ConfigError> {
        Err(ConfigError::Validation(
            "array fields cannot use env:/file: references".to_owned(),
        ))
    }
}

macro_rules! impl_resolve_leaf_enum {
    ($($ty:path),* $(,)?) => {
        $(
            impl ResolveLeaf for $ty {
                fn from_resolved_str(s: &str) -> Result<Self, ConfigError> {
                    parse_toml_scalar(s)
                }
            }
        )*
    };
}

impl_resolve_leaf_enum!(
    crate::enums::LogLevel,
    crate::enums::LogFormat,
    crate::enums::SameSite,
    crate::enums::HashingAlgorithm,
    crate::enums::TotpAlgorithm,
    crate::enums::UserVerification,
    crate::enums::ResidentKey,
    crate::enums::JwtAlgorithm,
);

#[macro_export]
macro_rules! ref_val {
    ($name:ident, $ty:ty, $val:expr) => {
        fn $name() -> $crate::ref_or::RefOr<$ty> {
            $crate::ref_or::RefOr::Value($val)
        }
    };
}
