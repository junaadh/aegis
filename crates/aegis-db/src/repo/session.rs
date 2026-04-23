use aegis_app::{AppError, SessionRepo};
use aegis_core::{Session, SessionId, UserId};
use sqlx::{Executor, PgPool, Postgres, Transaction};

use crate::repo::pg_repos::TxPtr;
use crate::row::SessionRow;

pub struct PgSessionRepo {
    pool: PgPool,
}

impl PgSessionRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

pub struct PgTxSessionRepo {
    tx: TxPtr,
}

unsafe impl Send for PgTxSessionRepo {}
unsafe impl Sync for PgTxSessionRepo {}

impl PgTxSessionRepo {
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

fn map_session(row: SessionRow) -> Result<Session, AppError> {
    row.try_into().map_err(infra_error)
}

async fn get_by_token_hash_impl<'e, E>(executor: E, hash: &[u8; 32]) -> Result<Option<Session>, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query_as::<_, SessionRow>(
        "SELECT id, token_hash, user_id, guest_id, expires_at, last_seen_at, mfa_verified, user_agent, ip_address, metadata FROM sessions WHERE token_hash = $1",
    )
    .bind(hash.as_slice())
    .fetch_optional(executor)
    .await
    .map_err(infra_error)?;

    row.map(map_session).transpose()
}

async fn insert_impl<'e, E>(executor: E, session: &Session) -> Result<(), AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let (user_id, guest_id) = match session.identity {
        aegis_core::SessionIdentity::User(id) => (Some(id.as_uuid()), None),
        aegis_core::SessionIdentity::Guest(id) => (None, Some(id.as_uuid())),
    };

    sqlx::query(
        "INSERT INTO sessions (id, token_hash, user_id, guest_id, expires_at, last_seen_at, mfa_verified, user_agent, ip_address, metadata) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(session.id.as_uuid())
    .bind(session.token_hash.as_slice())
    .bind(user_id)
    .bind(guest_id)
    .bind(session.expires_at)
    .bind(session.last_seen_at)
    .bind(session.mfa_verified)
    .bind(session.user_agent.as_deref())
    .bind(session.ip_address.as_deref())
    .bind(metadata_json(&session.metadata)?)
    .execute(executor)
    .await
    .map_err(infra_error)?;

    Ok(())
}

async fn update_impl<'e, E>(executor: E, session: &Session) -> Result<(), AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let (user_id, guest_id) = match session.identity {
        aegis_core::SessionIdentity::User(id) => (Some(id.as_uuid()), None),
        aegis_core::SessionIdentity::Guest(id) => (None, Some(id.as_uuid())),
    };

    sqlx::query(
        "UPDATE sessions SET token_hash = $2, user_id = $3, guest_id = $4, expires_at = $5, last_seen_at = $6, mfa_verified = $7, user_agent = $8, ip_address = $9, metadata = $10 WHERE id = $1",
    )
    .bind(session.id.as_uuid())
    .bind(session.token_hash.as_slice())
    .bind(user_id)
    .bind(guest_id)
    .bind(session.expires_at)
    .bind(session.last_seen_at)
    .bind(session.mfa_verified)
    .bind(session.user_agent.as_deref())
    .bind(session.ip_address.as_deref())
    .bind(metadata_json(&session.metadata)?)
    .execute(executor)
    .await
    .map_err(infra_error)?;

    Ok(())
}

async fn delete_by_id_impl<'e, E>(executor: E, id: SessionId) -> Result<(), AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query("DELETE FROM sessions WHERE id = $1")
        .bind(id.as_uuid())
        .execute(executor)
        .await
        .map_err(infra_error)?;
    Ok(())
}

async fn delete_by_user_id_impl<'e, E>(executor: E, user_id: UserId) -> Result<(), AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(user_id.as_uuid())
        .execute(executor)
        .await
        .map_err(infra_error)?;
    Ok(())
}

#[async_trait::async_trait]
impl SessionRepo for PgSessionRepo {
    async fn get_by_token_hash(&self, hash: &[u8; 32]) -> Result<Option<Session>, AppError> {
        get_by_token_hash_impl(&self.pool, hash).await
    }

    async fn insert(&mut self, session: &Session) -> Result<(), AppError> {
        insert_impl(&self.pool, session).await
    }

    async fn update(&mut self, session: &Session) -> Result<(), AppError> {
        update_impl(&self.pool, session).await
    }

    async fn delete_by_id(&mut self, id: SessionId) -> Result<(), AppError> {
        delete_by_id_impl(&self.pool, id).await
    }

    async fn delete_by_user_id(&mut self, user_id: UserId) -> Result<(), AppError> {
        delete_by_user_id_impl(&self.pool, user_id).await
    }
}

#[async_trait::async_trait]
impl SessionRepo for PgTxSessionRepo {
    async fn get_by_token_hash(&self, hash: &[u8; 32]) -> Result<Option<Session>, AppError> {
        get_by_token_hash_impl(self.tx().as_mut(), hash).await
    }

    async fn insert(&mut self, session: &Session) -> Result<(), AppError> {
        insert_impl(self.tx().as_mut(), session).await
    }

    async fn update(&mut self, session: &Session) -> Result<(), AppError> {
        update_impl(self.tx().as_mut(), session).await
    }

    async fn delete_by_id(&mut self, id: SessionId) -> Result<(), AppError> {
        delete_by_id_impl(self.tx().as_mut(), id).await
    }

    async fn delete_by_user_id(&mut self, user_id: UserId) -> Result<(), AppError> {
        delete_by_user_id_impl(self.tx().as_mut(), user_id).await
    }
}
