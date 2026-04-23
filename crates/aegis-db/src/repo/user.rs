use aegis_app::{AppError, UserRepo};
use aegis_core::User;
use sqlx::{Executor, PgPool, Postgres, Transaction};

use crate::repo::pg_repos::TxPtr;
use crate::row::UserRow;

pub struct PgUserRepo {
    pool: PgPool,
}

impl PgUserRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub(crate) fn pool(&self) -> &PgPool {
        &self.pool
    }
}

pub struct PgTxUserRepo {
    tx: TxPtr,
}

unsafe impl Send for PgTxUserRepo {}
unsafe impl Sync for PgTxUserRepo {}

impl PgTxUserRepo {
    pub(crate) fn new(tx: TxPtr) -> Self {
        Self { tx }
    }

    fn tx(&self) -> &mut Transaction<'static, Postgres> {
        unsafe { self.tx.as_ptr().as_mut().expect("transaction pointer must be valid") }
    }
}

fn infra_error(err: impl std::fmt::Display) -> AppError {
    AppError::Infrastructure(err.to_string())
}

fn metadata_json(metadata: &aegis_core::Metadata) -> Result<serde_json::Value, AppError> {
    serde_json::from_str(metadata.as_str()).map_err(infra_error)
}

fn map_user(row: UserRow) -> Result<User, AppError> {
    row.try_into().map_err(infra_error)
}

async fn get_by_id_impl<'e, E>(executor: E, id: aegis_core::UserId) -> Result<Option<User>, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query_as::<_, UserRow>(
        "SELECT id, email, email_verified_at, display_name, status, metadata, created_at, updated_at, deleted_at FROM users WHERE id = $1",
    )
    .bind(id.as_uuid())
    .fetch_optional(executor)
    .await
    .map_err(infra_error)?;

    row.map(map_user).transpose()
}

async fn get_by_email_impl<'e, E>(executor: E, email: &str) -> Result<Option<User>, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query_as::<_, UserRow>(
        "SELECT id, email, email_verified_at, display_name, status, metadata, created_at, updated_at, deleted_at FROM users WHERE LOWER(email) = LOWER($1)",
    )
    .bind(email)
    .fetch_optional(executor)
    .await
    .map_err(infra_error)?;

    row.map(map_user).transpose()
}

async fn email_exists_impl<'e, E>(executor: E, email: &str) -> Result<bool, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let exists = sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM users WHERE LOWER(email) = LOWER($1))")
        .bind(email)
        .fetch_one(executor)
        .await
        .map_err(infra_error)?;

    Ok(exists)
}

async fn insert_impl<'e, E>(executor: E, user: &User) -> Result<(), AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query(
        "INSERT INTO users (id, email, email_verified_at, display_name, status, metadata, created_at, updated_at, deleted_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(user.id.as_uuid())
    .bind(user.email.as_str())
    .bind(user.email_verified_at)
    .bind(user.display_name.as_str())
    .bind(user.status.to_string())
    .bind(metadata_json(&user.metadata)?)
    .bind(user.created_at)
    .bind(user.updated_at)
    .bind(user.deleted_at)
    .execute(executor)
    .await
    .map_err(infra_error)?;

    Ok(())
}

async fn update_impl<'e, E>(executor: E, user: &User) -> Result<(), AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query(
        "UPDATE users SET email = $2, email_verified_at = $3, display_name = $4, status = $5, metadata = $6, created_at = $7, updated_at = $8, deleted_at = $9 WHERE id = $1",
    )
    .bind(user.id.as_uuid())
    .bind(user.email.as_str())
    .bind(user.email_verified_at)
    .bind(user.display_name.as_str())
    .bind(user.status.to_string())
    .bind(metadata_json(&user.metadata)?)
    .bind(user.created_at)
    .bind(user.updated_at)
    .bind(user.deleted_at)
    .execute(executor)
    .await
    .map_err(infra_error)?;

    Ok(())
}

#[async_trait::async_trait]
impl UserRepo for PgUserRepo {
    async fn get_by_id(&self, id: aegis_core::UserId) -> Result<Option<User>, AppError> {
        get_by_id_impl(&self.pool, id).await
    }

    async fn get_by_email(&self, email: &str) -> Result<Option<User>, AppError> {
        get_by_email_impl(&self.pool, email).await
    }

    async fn email_exists(&self, email: &str) -> Result<bool, AppError> {
        email_exists_impl(&self.pool, email).await
    }

    async fn insert(&mut self, user: &User) -> Result<(), AppError> {
        insert_impl(&self.pool, user).await
    }

    async fn update(&mut self, user: &User) -> Result<(), AppError> {
        update_impl(&self.pool, user).await
    }
}

#[async_trait::async_trait]
impl UserRepo for PgTxUserRepo {
    async fn get_by_id(&self, id: aegis_core::UserId) -> Result<Option<User>, AppError> {
        get_by_id_impl(self.tx().as_mut(), id).await
    }

    async fn get_by_email(&self, email: &str) -> Result<Option<User>, AppError> {
        get_by_email_impl(self.tx().as_mut(), email).await
    }

    async fn email_exists(&self, email: &str) -> Result<bool, AppError> {
        email_exists_impl(self.tx().as_mut(), email).await
    }

    async fn insert(&mut self, user: &User) -> Result<(), AppError> {
        insert_impl(self.tx().as_mut(), user).await
    }

    async fn update(&mut self, user: &User) -> Result<(), AppError> {
        update_impl(self.tx().as_mut(), user).await
    }
}
