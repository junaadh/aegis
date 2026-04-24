use aegis_app::{AppError, PendingTokenRepo};
use aegis_core::{PendingToken, PendingTokenPurpose};
use sqlx::{Executor, PgPool, Postgres, Transaction};

use crate::repo::pg_repos::TxPtr;
use crate::row::{EmailVerificationTokenRow, PasswordResetTokenRow};

pub struct PgPendingTokenRepo {
    pool: PgPool,
}

impl PgPendingTokenRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

pub struct PgTxPendingTokenRepo {
    tx: TxPtr,
}

unsafe impl Send for PgTxPendingTokenRepo {}
unsafe impl Sync for PgTxPendingTokenRepo {}

impl PgTxPendingTokenRepo {
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

async fn get_by_hash_impl<'e, E>(
    executor: E,
    hash: &[u8; 32],
    purpose: PendingTokenPurpose,
) -> Result<Option<PendingToken>, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    match purpose {
        PendingTokenPurpose::EmailVerification => {
            let row = sqlx::query_as::<_, EmailVerificationTokenRow>(
                "SELECT id, user_id, token_hash, expires_at, created_at FROM email_verification_tokens WHERE token_hash = $1",
            )
            .bind(hash.as_slice())
            .fetch_optional(executor)
            .await
            .map_err(infra_error)?;

            row.map(TryInto::try_into).transpose().map_err(infra_error)
        }
        PendingTokenPurpose::PasswordReset => {
            let row = sqlx::query_as::<_, PasswordResetTokenRow>(
                "SELECT id, user_id, token_hash, expires_at, created_at FROM password_reset_tokens WHERE token_hash = $1",
            )
            .bind(hash.as_slice())
            .fetch_optional(executor)
            .await
            .map_err(infra_error)?;

            row.map(TryInto::try_into).transpose().map_err(infra_error)
        }
    }
}

async fn insert_impl<'e, E>(
    executor: E,
    token: &PendingToken,
) -> Result<(), AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let sql = match token.purpose {
        PendingTokenPurpose::EmailVerification => {
            "INSERT INTO email_verification_tokens (id, user_id, token_hash, expires_at, created_at) VALUES ($1, $2, $3, $4, $5)"
        }
        PendingTokenPurpose::PasswordReset => {
            "INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, created_at) VALUES ($1, $2, $3, $4, $5)"
        }
    };

    sqlx::query(sql)
        .bind(token.id)
        .bind(token.user_id.as_uuid())
        .bind(token.token_hash.as_slice())
        .bind(token.expires_at)
        .bind(token.created_at)
        .execute(executor)
        .await
        .map_err(infra_error)?;

    Ok(())
}

async fn delete_by_hash_impl<'e, E>(
    executor: E,
    hash: &[u8; 32],
) -> Result<(), AppError>
where
    E: Executor<'e, Database = Postgres> + Copy,
{
    sqlx::query("DELETE FROM email_verification_tokens WHERE token_hash = $1")
        .bind(hash.as_slice())
        .execute(executor)
        .await
        .map_err(infra_error)?;
    sqlx::query("DELETE FROM password_reset_tokens WHERE token_hash = $1")
        .bind(hash.as_slice())
        .execute(executor)
        .await
        .map_err(infra_error)?;
    Ok(())
}

async fn delete_by_hash_tx_impl(
    conn: &mut sqlx::PgConnection,
    hash: &[u8; 32],
) -> Result<(), AppError> {
    sqlx::query("DELETE FROM email_verification_tokens WHERE token_hash = $1")
        .bind(hash.as_slice())
        .execute(&mut *conn)
        .await
        .map_err(infra_error)?;
    sqlx::query("DELETE FROM password_reset_tokens WHERE token_hash = $1")
        .bind(hash.as_slice())
        .execute(&mut *conn)
        .await
        .map_err(infra_error)?;
    Ok(())
}

#[async_trait::async_trait]
impl PendingTokenRepo for PgPendingTokenRepo {
    async fn get_by_hash(
        &self,
        hash: &[u8; 32],
        purpose: PendingTokenPurpose,
    ) -> Result<Option<PendingToken>, AppError> {
        get_by_hash_impl(&self.pool, hash, purpose).await
    }

    async fn insert(&mut self, token: &PendingToken) -> Result<(), AppError> {
        insert_impl(&self.pool, token).await
    }

    async fn delete_by_hash(
        &mut self,
        hash: &[u8; 32],
    ) -> Result<(), AppError> {
        delete_by_hash_impl(&self.pool, hash).await
    }
}

#[async_trait::async_trait]
impl PendingTokenRepo for PgTxPendingTokenRepo {
    async fn get_by_hash(
        &self,
        hash: &[u8; 32],
        purpose: PendingTokenPurpose,
    ) -> Result<Option<PendingToken>, AppError> {
        get_by_hash_impl(self.tx().as_mut(), hash, purpose).await
    }

    async fn insert(&mut self, token: &PendingToken) -> Result<(), AppError> {
        insert_impl(self.tx().as_mut(), token).await
    }

    async fn delete_by_hash(
        &mut self,
        hash: &[u8; 32],
    ) -> Result<(), AppError> {
        delete_by_hash_tx_impl(self.tx().as_mut(), hash).await
    }
}
