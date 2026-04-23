use sqlx::migrate::Migrator;
use sqlx::PgPool;
use std::path::{Path, PathBuf};

pub struct MigrationRunner {
    pool: PgPool,
    migrations_dir: PathBuf,
}

impl MigrationRunner {
    pub fn new(pool: PgPool, migrations_dir: impl Into<PathBuf>) -> Self {
        Self {
            pool,
            migrations_dir: migrations_dir.into(),
        }
    }

    pub async fn up(&self) -> Result<(), sqlx::migrate::MigrateError> {
        let m = Migrator::new(self.migrations_dir.clone()).await?;
        m.run(&self.pool).await
    }

    pub async fn status(&self) -> Result<Vec<(String, bool)>, sqlx::migrate::MigrateError> {
        let m = Migrator::new(self.migrations_dir.clone()).await?;

        let applied: Vec<i64> = sqlx::query_scalar("SELECT version FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&self.pool)
            .await
            .unwrap_or_default();

        Ok(m
            .iter()
            .map(|mig| {
                let desc = format!("{} — {}", mig.version, mig.description);
                let is_applied = applied.contains(&mig.version);
                (desc, is_applied)
            })
            .collect())
    }

    pub fn create(name: &str, migrations_dir: &Path) -> Result<PathBuf, std::io::Error> {
        std::fs::create_dir_all(migrations_dir)?;

        let timestamp = chrono_like_timestamp();
        let filename = format!("{timestamp}_{name}.up.sql");
        let path = migrations_dir.join(&filename);

        std::fs::write(&path, "")?;
        Ok(path)
    }
}

fn chrono_like_timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", now.as_secs())
}
