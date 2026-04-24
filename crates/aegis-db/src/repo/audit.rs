use aegis_app::{AppError, AuditRepo};
use aegis_core::{Actor, NewAuditEntry};
use sqlx::{Executor, PgPool, Postgres, Transaction};

use crate::repo::pg_repos::TxPtr;

pub struct PgAuditRepo {
    pool: PgPool,
}

impl PgAuditRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

pub struct PgTxAuditRepo {
    tx: TxPtr,
}

unsafe impl Send for PgTxAuditRepo {}
unsafe impl Sync for PgTxAuditRepo {}

impl PgTxAuditRepo {
    pub(crate) fn new(tx: TxPtr) -> Self {
        Self { tx }
    }

    fn tx(&self) -> &mut Transaction<'static, Postgres> {
        unsafe {
            self.tx
                .as_ptr()
                .as_mut()
                .expect("transaction pointer must be valid")
        }
    }
}

fn infra_error(err: impl std::fmt::Display) -> AppError {
    AppError::Infrastructure(err.to_string())
}

fn metadata_json(
    metadata: &aegis_core::Metadata,
) -> Result<serde_json::Value, AppError> {
    serde_json::from_str(metadata.as_str()).map_err(infra_error)
}

async fn insert_impl<'e, E>(
    executor: E,
    entry: &NewAuditEntry,
) -> Result<(), AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let (actor_type, actor_id) = match &entry.actor {
        Actor::User(id) => ("user", Some(id.as_uuid())),
        Actor::Guest(id) => ("guest", Some(id.as_uuid())),
        Actor::Service(id) => ("service", uuid::Uuid::parse_str(id).ok()),
        Actor::System => ("system", None),
    };

    let (target_type, target_id) = match &entry.target {
        Some(target) => (Some(target.target_type.as_str()), target.target_id),
        None => (None, None),
    };

    sqlx::query(
        "INSERT INTO audit_logs (event_type, actor_type, actor_id, target_type, target_id, ip_address, user_agent, request_id, metadata, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(&entry.event_type)
    .bind(actor_type)
    .bind(actor_id)
    .bind(target_type)
    .bind(target_id)
    .bind(entry.ip_address.as_deref())
    .bind(entry.user_agent.as_deref())
    .bind(entry.request_id)
    .bind(metadata_json(&entry.metadata)?)
    .bind(entry.created_at)
    .execute(executor)
    .await
    .map_err(infra_error)?;

    Ok(())
}

#[async_trait::async_trait]
impl AuditRepo for PgAuditRepo {
    async fn insert(&mut self, entry: &NewAuditEntry) -> Result<(), AppError> {
        insert_impl(&self.pool, entry).await
    }
}

#[async_trait::async_trait]
impl AuditRepo for PgTxAuditRepo {
    async fn insert(&mut self, entry: &NewAuditEntry) -> Result<(), AppError> {
        insert_impl(self.tx().as_mut(), entry).await
    }
}
