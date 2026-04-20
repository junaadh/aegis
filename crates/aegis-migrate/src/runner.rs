use crate::error::MigrateError;
use sqlx::PgPool;
use std::path::PathBuf;
use tracing::info;

#[derive(Debug, Clone)]
pub struct Migration {
    pub version: i64,
    pub name: String,
    path: PathBuf,
}

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

    pub async fn ensure_schema_table(&self) -> Result<(), MigrateError> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                version BIGINT PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(MigrateError::Query)?;

        Ok(())
    }

    pub fn discover_migrations(&self) -> Result<Vec<Migration>, MigrateError> {
        let dir = &self.migrations_dir;
        if !dir.exists() {
            return Err(MigrateError::NoMigrationsDir(
                dir.display().to_string(),
            ));
        }

        let mut migrations = Vec::new();

        let entries = std::fs::read_dir(dir).map_err(|e| MigrateError::FileRead {
            path: dir.display().to_string(),
            source: e,
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| MigrateError::FileRead {
                path: dir.display().to_string(),
                source: e,
            })?;

            let path = entry.path();
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            if !file_name.ends_with(".up.sql") {
                continue;
            }

            let stem = file_name.trim_end_matches(".up.sql");
            let (version_str, name) = stem.split_once('_').unwrap_or((stem, "unnamed"));
            let version: i64 = version_str.parse().unwrap_or_else(|_| {
                panic!("migration filename must start with numeric version: {file_name}")
            });

            migrations.push(Migration {
                version,
                name: name.to_owned(),
                path,
            });
        }

        migrations.sort_by_key(|m| m.version);
        Ok(migrations)
    }

    pub async fn applied_versions(&self) -> Result<Vec<i64>, MigrateError> {
        let rows: Vec<(i64,)> =
            sqlx::query_as("SELECT version FROM schema_migrations ORDER BY version")
                .fetch_all(&self.pool)
                .await
                .map_err(MigrateError::Query)?;

        Ok(rows.into_iter().map(|(v,)| v).collect())
    }

    pub async fn up(&self) -> Result<Vec<Migration>, MigrateError> {
        self.ensure_schema_table().await?;

        let all = self.discover_migrations()?;
        let applied = self.applied_versions().await?;
        let pending: Vec<&Migration> = all
            .iter()
            .filter(|m| !applied.contains(&m.version))
            .collect();

        if pending.is_empty() {
            info!("no pending migrations");
            return Ok(all);
        }

        let total = pending.len();
        for (i, migration) in pending.iter().enumerate() {
            info!(
                "applying migration [{}/{}] {}",
                i + 1,
                total,
                migration.name
            );

            let sql = std::fs::read_to_string(&migration.path).map_err(|e| {
                MigrateError::FileRead {
                    path: migration.path.display().to_string(),
                    source: e,
                }
            })?;

            let mut tx = self.pool.begin().await.map_err(MigrateError::Query)?;

            for statement in split_statements(&sql) {
                if statement.trim().is_empty() {
                    continue;
                }
                sqlx::query(statement)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| MigrateError::Partial {
                        applied: i,
                        total,
                        error: e,
                    })?;
            }

            sqlx::query(
                "INSERT INTO schema_migrations (version, name) VALUES ($1, $2)",
            )
            .bind(migration.version)
            .bind(&migration.name)
            .execute(&mut *tx)
            .await
            .map_err(|e| MigrateError::Partial {
                applied: i,
                total,
                error: e,
            })?;

            tx.commit().await.map_err(MigrateError::Query)?;
        }

        info!("applied {total} migration(s)");
        Ok(all)
    }

    pub async fn status(&self) -> Result<Vec<(Migration, bool)>, MigrateError> {
        self.ensure_schema_table().await?;

        let all = self.discover_migrations()?;
        let applied = self.applied_versions().await?;

        Ok(all
            .into_iter()
            .map(|m| {
                let is_applied = applied.contains(&m.version);
                (m, is_applied)
            })
            .collect())
    }

    pub fn create(name: &str, migrations_dir: &PathBuf) -> Result<PathBuf, MigrateError> {
        std::fs::create_dir_all(migrations_dir).map_err(|e| MigrateError::FileRead {
            path: migrations_dir.display().to_string(),
            source: e,
        })?;

        let timestamp = chrono_like_timestamp();
        let filename = format!("{timestamp}_{name}.up.sql");
        let path = migrations_dir.join(&filename);

        std::fs::write(&path, "").map_err(|e| MigrateError::FileRead {
            path: path.display().to_string(),
            source: e,
        })?;

        Ok(path)
    }
}

fn split_statements(sql: &str) -> Vec<&str> {
    sql.split(';').collect()
}

fn chrono_like_timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", now.as_secs())
}
