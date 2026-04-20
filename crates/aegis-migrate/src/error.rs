use std::fmt;

#[derive(Debug)]
pub enum MigrateError {
    Connect(sqlx::Error),
    Query(sqlx::Error),
    FileRead { path: String, source: std::io::Error },
    NoMigrationsDir(String),
    Partial { applied: usize, total: usize, error: sqlx::Error },
}

impl fmt::Display for MigrateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "database connection failed: {e}"),
            Self::Query(e) => write!(f, "migration query failed: {e}"),
            Self::FileRead { path, source } => write!(f, "failed to read '{path}': {source}"),
            Self::NoMigrationsDir(dir) => write!(f, "migrations directory not found: {dir}"),
            Self::Partial { applied, total, error } => {
                write!(f, "partial migration: {applied}/{total} applied, error: {error}")
            }
        }
    }
}

impl std::error::Error for MigrateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connect(e) | Self::Query(e) => Some(e),
            Self::FileRead { source, .. } => Some(source),
            Self::Partial { error, .. } => Some(error),
            _ => None,
        }
    }
}
