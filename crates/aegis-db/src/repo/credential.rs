use aegis_app::{AppError, CredentialRepo, CredentialSummary};
use aegis_core::{
    CredentialKind, PasskeyCredential, PasswordCredential, RecoveryCode, RecoveryCodeState,
    TotpCredential, UserId,
};
use sqlx::{Executor, FromRow, PgPool, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::repo::pg_repos::TxPtr;
use crate::row::{
    PasskeyCredentialRow, PasswordCredentialRow, RecoveryCodeRow, TotpCredentialRow,
};

pub struct PgCredentialRepo {
    pool: PgPool,
}

impl PgCredentialRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

pub struct PgTxCredentialRepo {
    tx: TxPtr,
}

unsafe impl Send for PgTxCredentialRepo {}
unsafe impl Sync for PgTxCredentialRepo {}

impl PgTxCredentialRepo {
    pub(crate) fn new(tx: TxPtr) -> Self {
        Self { tx }
    }

    fn tx(&self) -> &mut Transaction<'static, Postgres> {
        unsafe { self.tx.as_ptr().as_mut().expect("transaction pointer must be valid") }
    }
}

#[derive(FromRow)]
struct CredentialSummaryRow {
    id: Uuid,
    kind: String,
    created_at: OffsetDateTime,
    last_used_at: Option<OffsetDateTime>,
}

fn infra_error(err: impl std::fmt::Display) -> AppError {
    AppError::Infrastructure(err.to_string())
}

fn map_summary(row: CredentialSummaryRow) -> Result<CredentialSummary, AppError> {
    let kind = match row.kind.as_str() {
        "password" => CredentialKind::Password,
        "passkey" => CredentialKind::Passkey,
        "totp" => CredentialKind::Totp,
        other => return Err(AppError::Infrastructure(format!("unknown credential kind: {other}"))),
    };

    Ok(CredentialSummary {
        id: row.id,
        kind,
        created_at: row.created_at,
        last_used_at: row.last_used_at,
    })
}

async fn get_password_by_user_id_impl<'e, E>(
    executor: E,
    user_id: UserId,
) -> Result<Option<PasswordCredential>, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query_as::<_, PasswordCredentialRow>(
        "SELECT id, user_id, hash, algorithm_version, created_at, updated_at, last_used_at FROM password_credentials WHERE user_id = $1",
    )
    .bind(user_id.as_uuid())
    .fetch_optional(executor)
    .await
    .map_err(infra_error)?;

    Ok(row.map(Into::into))
}

async fn list_by_user_id_impl<'e, E>(executor: E, user_id: UserId) -> Result<Vec<CredentialSummary>, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let rows = sqlx::query_as::<_, CredentialSummaryRow>(
        "SELECT id, 'password' AS kind, created_at, last_used_at FROM password_credentials WHERE user_id = $1
         UNION ALL
         SELECT id, 'passkey' AS kind, created_at, last_used_at FROM passkey_credentials WHERE user_id = $1
         UNION ALL
         SELECT id, 'totp' AS kind, created_at, NULL::timestamptz AS last_used_at FROM totp_credentials WHERE user_id = $1
         ORDER BY created_at",
    )
    .bind(user_id.as_uuid())
    .fetch_all(executor)
    .await
    .map_err(infra_error)?;

    rows.into_iter().map(map_summary).collect()
}

async fn get_totp_by_user_id_impl<'e, E>(executor: E, user_id: UserId) -> Result<Option<TotpCredential>, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query_as::<_, TotpCredentialRow>(
        "SELECT id, user_id, secret_encrypted, nonce, algorithm, digits, period, enabled, created_at, updated_at FROM totp_credentials WHERE user_id = $1",
    )
    .bind(user_id.as_uuid())
    .fetch_optional(executor)
    .await
    .map_err(infra_error)?;

    row.map(TryInto::try_into).transpose().map_err(infra_error)
}

async fn get_recovery_code_by_hash_impl<'e, E>(executor: E, hash: &str) -> Result<Option<RecoveryCode>, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query_as::<_, RecoveryCodeRow>(
        "SELECT id, user_id, code_hash, used_at, created_at FROM recovery_codes WHERE code_hash = $1",
    )
    .bind(hash)
    .fetch_optional(executor)
    .await
    .map_err(infra_error)?;

    Ok(row.map(Into::into))
}

async fn get_passkey_by_credential_id_impl<'e, E>(
    executor: E,
    credential_id: &str,
) -> Result<Option<PasskeyCredential>, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query_as::<_, PasskeyCredentialRow>(
        "SELECT id, user_id, credential_id, public_key, attestation_object, authenticator_data, sign_count, transports, backup_eligible, backup_state, created_at, last_used_at FROM passkey_credentials WHERE credential_id = $1",
    )
    .bind(credential_id)
    .fetch_optional(executor)
    .await
    .map_err(infra_error)?;

    Ok(row.map(Into::into))
}

async fn insert_password_impl<'e, E>(executor: E, cred: &PasswordCredential) -> Result<(), AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query(
        "INSERT INTO password_credentials (id, user_id, hash, algorithm_version, created_at, updated_at, last_used_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(cred.id.as_uuid())
    .bind(cred.user_id.as_uuid())
    .bind(&cred.hash)
    .bind(cred.algorithm_version)
    .bind(cred.created_at)
    .bind(cred.updated_at)
    .bind(cred.last_used_at)
    .execute(executor)
    .await
    .map_err(infra_error)?;
    Ok(())
}

async fn update_password_impl<'e, E>(executor: E, cred: &PasswordCredential) -> Result<(), AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query(
        "UPDATE password_credentials SET user_id = $2, hash = $3, algorithm_version = $4, created_at = $5, updated_at = $6, last_used_at = $7 WHERE id = $1",
    )
    .bind(cred.id.as_uuid())
    .bind(cred.user_id.as_uuid())
    .bind(&cred.hash)
    .bind(cred.algorithm_version)
    .bind(cred.created_at)
    .bind(cred.updated_at)
    .bind(cred.last_used_at)
    .execute(executor)
    .await
    .map_err(infra_error)?;
    Ok(())
}

async fn delete_by_id_impl<'e, E>(executor: E, id: Uuid) -> Result<(), AppError>
where
    E: Executor<'e, Database = Postgres> + Copy,
{
    sqlx::query("DELETE FROM passkey_credentials WHERE id = $1")
        .bind(id)
        .execute(executor)
        .await
        .map_err(infra_error)?;
    sqlx::query("DELETE FROM totp_credentials WHERE id = $1")
        .bind(id)
        .execute(executor)
        .await
        .map_err(infra_error)?;
    sqlx::query("DELETE FROM password_credentials WHERE id = $1")
        .bind(id)
        .execute(executor)
        .await
        .map_err(infra_error)?;
    sqlx::query("DELETE FROM recovery_codes WHERE id = $1")
        .bind(id)
        .execute(executor)
        .await
        .map_err(infra_error)?;
    Ok(())
}

async fn delete_by_id_tx_impl(
    conn: &mut sqlx::PgConnection,
    id: Uuid,
) -> Result<(), AppError> {
    sqlx::query("DELETE FROM passkey_credentials WHERE id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await
        .map_err(infra_error)?;
    sqlx::query("DELETE FROM totp_credentials WHERE id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await
        .map_err(infra_error)?;
    sqlx::query("DELETE FROM password_credentials WHERE id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await
        .map_err(infra_error)?;
    sqlx::query("DELETE FROM recovery_codes WHERE id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await
        .map_err(infra_error)?;
    Ok(())
}

async fn insert_totp_impl<'e, E>(executor: E, cred: &TotpCredential) -> Result<(), AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query(
        "INSERT INTO totp_credentials (id, user_id, secret_encrypted, nonce, algorithm, digits, period, enabled, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(cred.id.as_uuid())
    .bind(cred.user_id.as_uuid())
    .bind(&cred.secret_encrypted)
    .bind(&cred.nonce)
    .bind(cred.algorithm.to_string())
    .bind(cred.digits)
    .bind(cred.period)
    .bind(cred.enabled)
    .bind(cred.created_at)
    .bind(cred.updated_at)
    .execute(executor)
    .await
    .map_err(infra_error)?;
    Ok(())
}

async fn update_totp_impl<'e, E>(executor: E, cred: &TotpCredential) -> Result<(), AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query(
        "UPDATE totp_credentials SET user_id = $2, secret_encrypted = $3, nonce = $4, algorithm = $5, digits = $6, period = $7, enabled = $8, created_at = $9, updated_at = $10 WHERE id = $1",
    )
    .bind(cred.id.as_uuid())
    .bind(cred.user_id.as_uuid())
    .bind(&cred.secret_encrypted)
    .bind(&cred.nonce)
    .bind(cred.algorithm.to_string())
    .bind(cred.digits)
    .bind(cred.period)
    .bind(cred.enabled)
    .bind(cred.created_at)
    .bind(cred.updated_at)
    .execute(executor)
    .await
    .map_err(infra_error)?;
    Ok(())
}

async fn insert_recovery_codes_impl<'e, E>(executor: E, codes: &[RecoveryCode]) -> Result<(), AppError>
where
    E: Executor<'e, Database = Postgres> + Copy,
{
    for code in codes {
        let used_at = match code.state {
            RecoveryCodeState::Unused => None,
            RecoveryCodeState::Used { at } => Some(at),
        };

        sqlx::query(
            "INSERT INTO recovery_codes (id, user_id, code_hash, used_at, created_at) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(code.id.as_uuid())
        .bind(code.user_id.as_uuid())
        .bind(&code.code_hash)
        .bind(used_at)
        .bind(code.created_at)
        .execute(executor)
        .await
        .map_err(infra_error)?;
    }
    Ok(())
}

async fn insert_recovery_codes_tx_impl(
    conn: &mut sqlx::PgConnection,
    codes: &[RecoveryCode],
) -> Result<(), AppError> {
    for code in codes {
        let used_at = match code.state {
            RecoveryCodeState::Unused => None,
            RecoveryCodeState::Used { at } => Some(at),
        };

        sqlx::query(
            "INSERT INTO recovery_codes (id, user_id, code_hash, used_at, created_at) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(code.id.as_uuid())
        .bind(code.user_id.as_uuid())
        .bind(&code.code_hash)
        .bind(used_at)
        .bind(code.created_at)
        .execute(&mut *conn)
        .await
        .map_err(infra_error)?;
    }

    Ok(())
}

async fn update_recovery_code_impl<'e, E>(executor: E, code: &RecoveryCode) -> Result<(), AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let used_at = match code.state {
        RecoveryCodeState::Unused => None,
        RecoveryCodeState::Used { at } => Some(at),
    };

    sqlx::query("UPDATE recovery_codes SET user_id = $2, code_hash = $3, used_at = $4, created_at = $5 WHERE id = $1")
        .bind(code.id.as_uuid())
        .bind(code.user_id.as_uuid())
        .bind(&code.code_hash)
        .bind(used_at)
        .bind(code.created_at)
        .execute(executor)
        .await
        .map_err(infra_error)?;
    Ok(())
}

async fn delete_recovery_codes_by_user_id_impl<'e, E>(executor: E, user_id: UserId) -> Result<(), AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1")
        .bind(user_id.as_uuid())
        .execute(executor)
        .await
        .map_err(infra_error)?;
    Ok(())
}

async fn insert_passkey_impl<'e, E>(executor: E, cred: &PasskeyCredential) -> Result<(), AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query(
        "INSERT INTO passkey_credentials (id, user_id, credential_id, public_key, attestation_object, authenticator_data, sign_count, transports, backup_eligible, backup_state, created_at, last_used_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind(cred.id.as_uuid())
    .bind(cred.user_id.as_uuid())
    .bind(&cred.credential_id)
    .bind(&cred.public_key)
    .bind(&cred.attestation_object)
    .bind(&cred.authenticator_data)
    .bind(cred.sign_count)
    .bind(&cred.transports)
    .bind(cred.backup_eligible)
    .bind(cred.backup_state)
    .bind(cred.created_at)
    .bind(cred.last_used_at)
    .execute(executor)
    .await
    .map_err(infra_error)?;
    Ok(())
}

async fn update_passkey_impl<'e, E>(executor: E, cred: &PasskeyCredential) -> Result<(), AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query(
        "UPDATE passkey_credentials SET user_id = $2, credential_id = $3, public_key = $4, attestation_object = $5, authenticator_data = $6, sign_count = $7, transports = $8, backup_eligible = $9, backup_state = $10, created_at = $11, last_used_at = $12 WHERE id = $1",
    )
    .bind(cred.id.as_uuid())
    .bind(cred.user_id.as_uuid())
    .bind(&cred.credential_id)
    .bind(&cred.public_key)
    .bind(&cred.attestation_object)
    .bind(&cred.authenticator_data)
    .bind(cred.sign_count)
    .bind(&cred.transports)
    .bind(cred.backup_eligible)
    .bind(cred.backup_state)
    .bind(cred.created_at)
    .bind(cred.last_used_at)
    .execute(executor)
    .await
    .map_err(infra_error)?;
    Ok(())
}

#[async_trait::async_trait]
impl CredentialRepo for PgCredentialRepo {
    async fn get_password_by_user_id(&self, user_id: UserId) -> Result<Option<PasswordCredential>, AppError> {
        get_password_by_user_id_impl(&self.pool, user_id).await
    }

    async fn list_by_user_id(&self, user_id: UserId) -> Result<Vec<CredentialSummary>, AppError> {
        list_by_user_id_impl(&self.pool, user_id).await
    }

    async fn get_totp_by_user_id(&self, user_id: UserId) -> Result<Option<TotpCredential>, AppError> {
        get_totp_by_user_id_impl(&self.pool, user_id).await
    }

    async fn get_recovery_code_by_hash(&self, hash: &str) -> Result<Option<RecoveryCode>, AppError> {
        get_recovery_code_by_hash_impl(&self.pool, hash).await
    }

    async fn get_passkey_by_credential_id(&self, credential_id: &str) -> Result<Option<PasskeyCredential>, AppError> {
        get_passkey_by_credential_id_impl(&self.pool, credential_id).await
    }

    async fn insert_password(&mut self, cred: &PasswordCredential) -> Result<(), AppError> {
        insert_password_impl(&self.pool, cred).await
    }

    async fn update_password(&mut self, cred: &PasswordCredential) -> Result<(), AppError> {
        update_password_impl(&self.pool, cred).await
    }

    async fn delete_by_id(&mut self, id: Uuid) -> Result<(), AppError> {
        delete_by_id_impl(&self.pool, id).await
    }

    async fn insert_totp(&mut self, cred: &TotpCredential) -> Result<(), AppError> {
        insert_totp_impl(&self.pool, cred).await
    }

    async fn update_totp(&mut self, cred: &TotpCredential) -> Result<(), AppError> {
        update_totp_impl(&self.pool, cred).await
    }

    async fn insert_recovery_codes(&mut self, codes: &[RecoveryCode]) -> Result<(), AppError> {
        insert_recovery_codes_impl(&self.pool, codes).await
    }

    async fn update_recovery_code(&mut self, code: &RecoveryCode) -> Result<(), AppError> {
        update_recovery_code_impl(&self.pool, code).await
    }

    async fn delete_recovery_codes_by_user_id(&mut self, user_id: UserId) -> Result<(), AppError> {
        delete_recovery_codes_by_user_id_impl(&self.pool, user_id).await
    }

    async fn insert_passkey(&mut self, cred: &PasskeyCredential) -> Result<(), AppError> {
        insert_passkey_impl(&self.pool, cred).await
    }

    async fn update_passkey(&mut self, cred: &PasskeyCredential) -> Result<(), AppError> {
        update_passkey_impl(&self.pool, cred).await
    }
}

#[async_trait::async_trait]
impl CredentialRepo for PgTxCredentialRepo {
    async fn get_password_by_user_id(&self, user_id: UserId) -> Result<Option<PasswordCredential>, AppError> {
        get_password_by_user_id_impl(self.tx().as_mut(), user_id).await
    }

    async fn list_by_user_id(&self, user_id: UserId) -> Result<Vec<CredentialSummary>, AppError> {
        list_by_user_id_impl(self.tx().as_mut(), user_id).await
    }

    async fn get_totp_by_user_id(&self, user_id: UserId) -> Result<Option<TotpCredential>, AppError> {
        get_totp_by_user_id_impl(self.tx().as_mut(), user_id).await
    }

    async fn get_recovery_code_by_hash(&self, hash: &str) -> Result<Option<RecoveryCode>, AppError> {
        get_recovery_code_by_hash_impl(self.tx().as_mut(), hash).await
    }

    async fn get_passkey_by_credential_id(&self, credential_id: &str) -> Result<Option<PasskeyCredential>, AppError> {
        get_passkey_by_credential_id_impl(self.tx().as_mut(), credential_id).await
    }

    async fn insert_password(&mut self, cred: &PasswordCredential) -> Result<(), AppError> {
        insert_password_impl(self.tx().as_mut(), cred).await
    }

    async fn update_password(&mut self, cred: &PasswordCredential) -> Result<(), AppError> {
        update_password_impl(self.tx().as_mut(), cred).await
    }

    async fn delete_by_id(&mut self, id: Uuid) -> Result<(), AppError> {
        delete_by_id_tx_impl(self.tx().as_mut(), id).await
    }

    async fn insert_totp(&mut self, cred: &TotpCredential) -> Result<(), AppError> {
        insert_totp_impl(self.tx().as_mut(), cred).await
    }

    async fn update_totp(&mut self, cred: &TotpCredential) -> Result<(), AppError> {
        update_totp_impl(self.tx().as_mut(), cred).await
    }

    async fn insert_recovery_codes(&mut self, codes: &[RecoveryCode]) -> Result<(), AppError> {
        insert_recovery_codes_tx_impl(self.tx().as_mut(), codes).await
    }

    async fn update_recovery_code(&mut self, code: &RecoveryCode) -> Result<(), AppError> {
        update_recovery_code_impl(self.tx().as_mut(), code).await
    }

    async fn delete_recovery_codes_by_user_id(&mut self, user_id: UserId) -> Result<(), AppError> {
        delete_recovery_codes_by_user_id_impl(self.tx().as_mut(), user_id).await
    }

    async fn insert_passkey(&mut self, cred: &PasskeyCredential) -> Result<(), AppError> {
        insert_passkey_impl(self.tx().as_mut(), cred).await
    }

    async fn update_passkey(&mut self, cred: &PasskeyCredential) -> Result<(), AppError> {
        update_passkey_impl(self.tx().as_mut(), cred).await
    }
}
