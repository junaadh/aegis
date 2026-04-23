use aegis_app::{AppError, GuestRepo};
use aegis_core::Guest;
use sqlx::{Executor, PgPool, Postgres, Transaction};

use crate::repo::pg_repos::TxPtr;
use crate::row::GuestRow;

pub struct PgGuestRepo {
    pool: PgPool,
}

impl PgGuestRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

pub struct PgTxGuestRepo {
    tx: TxPtr,
}

unsafe impl Send for PgTxGuestRepo {}
unsafe impl Sync for PgTxGuestRepo {}

impl PgTxGuestRepo {
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

fn map_guest(row: GuestRow) -> Result<Guest, AppError> {
    row.try_into().map_err(infra_error)
}

async fn get_by_id_impl<'e, E>(executor: E, id: aegis_core::GuestId) -> Result<Option<Guest>, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query_as::<_, GuestRow>(
        "SELECT id, email, metadata, created_at, updated_at, converted_to, expires_at FROM guests WHERE id = $1",
    )
    .bind(id.as_uuid())
    .fetch_optional(executor)
    .await
    .map_err(infra_error)?;

    row.map(map_guest).transpose()
}

async fn insert_impl<'e, E>(executor: E, guest: &Guest) -> Result<(), AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query(
        "INSERT INTO guests (id, email, metadata, created_at, updated_at, converted_to, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(guest.id.as_uuid())
    .bind(guest.email.as_ref().map(|email| email.as_str()))
    .bind(metadata_json(&guest.metadata)?)
    .bind(guest.created_at)
    .bind(guest.updated_at)
    .bind(guest.converted_to.map(|id| id.as_uuid()))
    .bind(guest.expires_at)
    .execute(executor)
    .await
    .map_err(infra_error)?;

    Ok(())
}

async fn update_impl<'e, E>(executor: E, guest: &Guest) -> Result<(), AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query(
        "UPDATE guests SET email = $2, metadata = $3, created_at = $4, updated_at = $5, converted_to = $6, expires_at = $7 WHERE id = $1",
    )
    .bind(guest.id.as_uuid())
    .bind(guest.email.as_ref().map(|email| email.as_str()))
    .bind(metadata_json(&guest.metadata)?)
    .bind(guest.created_at)
    .bind(guest.updated_at)
    .bind(guest.converted_to.map(|id| id.as_uuid()))
    .bind(guest.expires_at)
    .execute(executor)
    .await
    .map_err(infra_error)?;

    Ok(())
}

#[async_trait::async_trait]
impl GuestRepo for PgGuestRepo {
    async fn get_by_id(&self, id: aegis_core::GuestId) -> Result<Option<Guest>, AppError> {
        get_by_id_impl(&self.pool, id).await
    }

    async fn insert(&mut self, guest: &Guest) -> Result<(), AppError> {
        insert_impl(&self.pool, guest).await
    }

    async fn update(&mut self, guest: &Guest) -> Result<(), AppError> {
        update_impl(&self.pool, guest).await
    }
}

#[async_trait::async_trait]
impl GuestRepo for PgTxGuestRepo {
    async fn get_by_id(&self, id: aegis_core::GuestId) -> Result<Option<Guest>, AppError> {
        get_by_id_impl(self.tx().as_mut(), id).await
    }

    async fn insert(&mut self, guest: &Guest) -> Result<(), AppError> {
        insert_impl(self.tx().as_mut(), guest).await
    }

    async fn update(&mut self, guest: &Guest) -> Result<(), AppError> {
        update_impl(self.tx().as_mut(), guest).await
    }
}
