use std::{fmt, io};

#[derive(Debug)]
pub enum ConfigError {
    Parse(toml::de::Error),
    Validation(String),
    MissingField(String),
    Io(io::Error),
    Serialize(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "config parse error: {e}"),
            Self::Validation(msg) => write!(f, "config validation error: {msg}"),
            Self::MissingField(field) => write!(f, "missing required field: {field}"),
            Self::Io(e) => write!(f, "config I/O error: {e}"),
            Self::Serialize(msg) => write!(f, "config serialization error: {msg}"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse(e) => Some(e),
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(e: toml::de::Error) -> Self {
        Self::Parse(e)
    }
}

impl From<io::Error> for ConfigError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
