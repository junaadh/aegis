use std::fmt;

#[derive(Debug)]
pub enum CacheError {
    Connection(String),
    Serialization(String),
    Backend(String),
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection(msg) => write!(f, "cache connection error: {msg}"),
            Self::Serialization(msg) => write!(f, "cache serialization error: {msg}"),
            Self::Backend(msg) => write!(f, "cache backend error: {msg}"),
        }
    }
}

impl std::error::Error for CacheError {}
