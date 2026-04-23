use aegis_app::{AppError, JobPayload, OutboxEntry, OutboxRepo};
use serde_json::json;
use sqlx::{Executor, FromRow, PgPool, Postgres, Transaction};
use time::OffsetDateTime;

use crate::repo::pg_repos::TxPtr;

pub struct PgOutboxRepo {
    pool: PgPool,
}

impl PgOutboxRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

pub struct PgTxOutboxRepo {
    tx: TxPtr,
}

unsafe impl Send for PgTxOutboxRepo {}
unsafe impl Sync for PgTxOutboxRepo {}

impl PgTxOutboxRepo {
    pub(crate) fn new(tx: TxPtr) -> Self {
        Self { tx }
    }

    fn tx(&self) -> &mut Transaction<'static, Postgres> {
        unsafe { self.tx.as_ptr().as_mut().expect("transaction pointer must be valid") }
    }
}

#[derive(FromRow)]
struct OutboxRow {
    id: i64,
    job_type: String,
    payload: String,
    attempts: i32,
    max_attempts: i32,
    created_at: OffsetDateTime,
    next_retry_at: Option<OffsetDateTime>,
}

fn infra_error(err: impl std::fmt::Display) -> AppError {
    AppError::Infrastructure(err.to_string())
}

fn serialize_payload(payload: &JobPayload) -> serde_json::Value {
    match payload {
        JobPayload::SendVerificationEmail { user_id, email, token } => {
            json!({ "user_id": user_id, "email": email, "token": token })
        }
        JobPayload::SendPasswordResetEmail { user_id, email, token } => {
            json!({ "user_id": user_id, "email": email, "token": token })
        }
        JobPayload::SendMfaEnrolledNotification { user_id } => json!({ "user_id": user_id }),
        JobPayload::CleanupExpiredSessions => json!({}),
        JobPayload::CleanupExpiredGuests => json!({}),
    }
}

fn map_outbox(row: OutboxRow) -> Result<OutboxEntry, AppError> {
    Ok(OutboxEntry {
        id: row.id,
        job_type: row.job_type,
        payload: row.payload,
        attempts: row.attempts.try_into().map_err(infra_error)?,
        max_attempts: row.max_attempts.try_into().map_err(infra_error)?,
        created_at: row.created_at,
        next_retry_at: row.next_retry_at,
    })
}

async fn enqueue_impl<'e, E>(executor: E, payload: &JobPayload) -> Result<(), AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query("INSERT INTO outbox (job_type, payload) VALUES ($1, $2)")
        .bind(payload.job_type())
        .bind(serialize_payload(payload))
        .execute(executor)
        .await
        .map_err(infra_error)?;
    Ok(())
}

async fn claim_pending_impl<'e, E>(executor: E, limit: usize) -> Result<Vec<OutboxEntry>, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let rows = sqlx::query_as::<_, OutboxRow>(
        "WITH claimed AS (
            SELECT id
            FROM outbox
            WHERE status = 'pending'
              AND (next_retry_at IS NULL OR next_retry_at <= NOW())
            ORDER BY created_at
            LIMIT $1
            FOR UPDATE SKIP LOCKED
        )
        UPDATE outbox o
        SET status = 'processing'
        FROM claimed
        WHERE o.id = claimed.id
        RETURNING o.id, o.job_type, o.payload::text AS payload, o.attempts, o.max_attempts, o.created_at, o.next_retry_at",
    )
    .bind(limit as i64)
    .fetch_all(executor)
    .await
    .map_err(infra_error)?;

    rows.into_iter().map(map_outbox).collect()
}

async fn mark_processed_impl<'e, E>(executor: E, id: i64) -> Result<(), AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query("UPDATE outbox SET status = 'completed', processed_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(executor)
        .await
        .map_err(infra_error)?;
    Ok(())
}

async fn mark_retry_impl<'e, E>(executor: E, id: i64, next_retry_at: OffsetDateTime) -> Result<(), AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query("UPDATE outbox SET status = 'pending', attempts = attempts + 1, next_retry_at = $2 WHERE id = $1")
        .bind(id)
        .bind(next_retry_at)
        .execute(executor)
        .await
        .map_err(infra_error)?;
    Ok(())
}

async fn mark_dead_lettered_impl<'e, E>(executor: E, id: i64) -> Result<(), AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query("UPDATE outbox SET status = 'dead_lettered', attempts = attempts + 1, processed_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(executor)
        .await
        .map_err(infra_error)?;
    Ok(())
}

#[async_trait::async_trait]
impl OutboxRepo for PgOutboxRepo {
    async fn enqueue(&mut self, payload: &JobPayload) -> Result<(), AppError> {
        enqueue_impl(&self.pool, payload).await
    }

    async fn claim_pending(&mut self, limit: usize) -> Result<Vec<OutboxEntry>, AppError> {
        claim_pending_impl(&self.pool, limit).await
    }

    async fn mark_processed(&mut self, id: i64) -> Result<(), AppError> {
        mark_processed_impl(&self.pool, id).await
    }

    async fn mark_retry(&mut self, id: i64, next_retry_at: OffsetDateTime) -> Result<(), AppError> {
        mark_retry_impl(&self.pool, id, next_retry_at).await
    }

    async fn mark_dead_lettered(&mut self, id: i64) -> Result<(), AppError> {
        mark_dead_lettered_impl(&self.pool, id).await
    }
}

#[async_trait::async_trait]
impl OutboxRepo for PgTxOutboxRepo {
    async fn enqueue(&mut self, payload: &JobPayload) -> Result<(), AppError> {
        enqueue_impl(self.tx().as_mut(), payload).await
    }

    async fn claim_pending(&mut self, limit: usize) -> Result<Vec<OutboxEntry>, AppError> {
        claim_pending_impl(self.tx().as_mut(), limit).await
    }

    async fn mark_processed(&mut self, id: i64) -> Result<(), AppError> {
        mark_processed_impl(self.tx().as_mut(), id).await
    }

    async fn mark_retry(&mut self, id: i64, next_retry_at: OffsetDateTime) -> Result<(), AppError> {
        mark_retry_impl(self.tx().as_mut(), id, next_retry_at).await
    }

    async fn mark_dead_lettered(&mut self, id: i64) -> Result<(), AppError> {
        mark_dead_lettered_impl(self.tx().as_mut(), id).await
    }
}
