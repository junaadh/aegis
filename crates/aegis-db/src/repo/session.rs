use aegis_app::{
    AdminSessionDetailResult, AdminSessionListItem, AdminSessionListQuery,
    AppError, PaginatedResult, SessionRepo, UserSessionSummary,
};
use aegis_core::{Session, SessionId, UserId};
use sqlx::{Executor, FromRow, PgPool, Postgres, QueryBuilder, Transaction};
use time::OffsetDateTime;

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

fn map_session(row: SessionRow) -> Result<Session, AppError> {
    row.try_into().map_err(infra_error)
}

async fn get_by_token_hash_impl<'e, E>(
    executor: E,
    hash: &[u8; 32],
) -> Result<Option<Session>, AppError>
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

async fn get_user_summary_impl<'e, E>(
    executor: E,
    user_id: UserId,
) -> Result<UserSessionSummary, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query_as::<_, (i64, Option<OffsetDateTime>)>(
        "SELECT COUNT(*) AS count, MAX(last_seen_at) AS last_seen_at FROM sessions WHERE user_id = $1",
    )
    .bind(user_id.as_uuid())
    .fetch_one(executor)
    .await
    .map_err(infra_error)?;

    Ok(UserSessionSummary {
        session_count: row.0 as u64,
        last_seen_at: row.1,
    })
}

async fn get_by_id_impl<'e, E>(
    executor: E,
    id: SessionId,
) -> Result<Option<Session>, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query_as::<_, SessionRow>(
        "SELECT id, token_hash, user_id, guest_id, expires_at, last_seen_at, mfa_verified, user_agent, ip_address, metadata FROM sessions WHERE id = $1",
    )
    .bind(id.as_uuid())
    .fetch_optional(executor)
    .await
    .map_err(infra_error)?;

    row.map(map_session).transpose()
}

async fn insert_impl<'e, E>(
    executor: E,
    session: &Session,
) -> Result<(), AppError>
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

async fn update_impl<'e, E>(
    executor: E,
    session: &Session,
) -> Result<(), AppError>
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

async fn delete_by_id_impl<'e, E>(
    executor: E,
    id: SessionId,
) -> Result<(), AppError>
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

async fn delete_by_user_id_impl<'e, E>(
    executor: E,
    user_id: UserId,
) -> Result<(), AppError>
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

#[derive(Debug, FromRow)]
struct AdminSessionListRow {
    id: uuid::Uuid,
    user_id: Option<uuid::Uuid>,
    guest_id: Option<uuid::Uuid>,
    expires_at: OffsetDateTime,
    last_seen_at: OffsetDateTime,
    mfa_verified: bool,
    user_agent: Option<String>,
    ip_address: Option<String>,
}

fn map_admin_session_list_row(
    row: AdminSessionListRow,
) -> AdminSessionListItem {
    let (identity_type, identity_id) = match (row.user_id, row.guest_id) {
        (Some(uid), None) => ("user".to_owned(), uid),
        (None, Some(gid)) => ("guest".to_owned(), gid),
        _ => ("unknown".to_owned(), uuid::Uuid::nil()),
    };
    AdminSessionListItem {
        id: row.id,
        identity_type,
        identity_id,
        expires_at: row.expires_at,
        last_seen_at: row.last_seen_at,
        mfa_verified: row.mfa_verified,
        user_agent: row.user_agent,
        ip_address: row.ip_address,
    }
}

fn push_session_filters(
    builder: &mut QueryBuilder<'_, Postgres>,
    query: &AdminSessionListQuery,
) {
    if let Some(user_id) = query.user_id {
        builder.push(" AND s.user_id = ");
        builder.push_bind(user_id);
    }
    if query.active_only.unwrap_or(false) {
        builder.push(" AND s.expires_at > NOW()");
    }
}

fn build_session_count_query(
    query: &AdminSessionListQuery,
) -> QueryBuilder<'static, Postgres> {
    let mut builder = QueryBuilder::<Postgres>::new(
        "SELECT COUNT(*) FROM sessions s WHERE 1 = 1",
    );
    push_session_filters(&mut builder, query);
    builder
}

fn build_session_rows_query(
    query: &AdminSessionListQuery,
    limit: i64,
    offset: i64,
) -> QueryBuilder<'static, Postgres> {
    let mut builder = QueryBuilder::<Postgres>::new(
        "SELECT s.id, s.user_id, s.guest_id, s.expires_at, s.last_seen_at, s.mfa_verified, s.user_agent, s.ip_address FROM sessions s WHERE 1 = 1",
    );
    push_session_filters(&mut builder, query);
    builder.push(" ORDER BY s.last_seen_at DESC, s.id ASC LIMIT ");
    builder.push_bind(limit);
    builder.push(" OFFSET ");
    builder.push_bind(offset);
    builder
}

async fn list_admin_impl<'e, E>(
    executor: E,
    query: &AdminSessionListQuery,
) -> Result<PaginatedResult<AdminSessionListItem>, AppError>
where
    E: Executor<'e, Database = Postgres> + Copy,
{
    let page = query.page.max(1);
    let per_page = query.per_page.clamp(1, 200);
    let offset = i64::from((page - 1) * per_page);
    let limit = i64::from(per_page);

    let total: i64 = build_session_count_query(query)
        .build_query_scalar()
        .fetch_one(executor)
        .await
        .map_err(infra_error)?;

    let rows = build_session_rows_query(query, limit, offset)
        .build_query_as::<AdminSessionListRow>()
        .fetch_all(executor)
        .await
        .map_err(infra_error)?;

    Ok(PaginatedResult {
        items: rows.into_iter().map(map_admin_session_list_row).collect(),
        page,
        per_page,
        total: total as u64,
    })
}

async fn get_admin_detail_impl<'e, E>(
    executor: E,
    id: SessionId,
) -> Result<Option<AdminSessionDetailResult>, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query_as::<_, SessionRow>(
        "SELECT id, token_hash, user_id, guest_id, expires_at, last_seen_at, mfa_verified, user_agent, ip_address, metadata FROM sessions WHERE id = $1",
    )
    .bind(id.as_uuid())
    .fetch_optional(executor)
    .await
    .map_err(infra_error)?;

    row.map(|row| {
        let (identity_type, identity_id) = match (row.user_id, row.guest_id) {
            (Some(uid), None) => ("user".to_owned(), uid),
            (None, Some(gid)) => ("guest".to_owned(), gid),
            _ => ("unknown".to_owned(), uuid::Uuid::nil()),
        };
        Ok(AdminSessionDetailResult {
            id: row.id,
            identity_type,
            identity_id,
            expires_at: row.expires_at,
            last_seen_at: row.last_seen_at,
            mfa_verified: row.mfa_verified,
            user_agent: row.user_agent,
            ip_address: row.ip_address,
            metadata: row.metadata,
        })
    })
    .transpose()
}

async fn count_active_impl<'e, E>(executor: E) -> Result<u64, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sessions WHERE expires_at > NOW()",
    )
    .fetch_one(executor)
    .await
    .map_err(infra_error)?;

    Ok(count as u64)
}

#[async_trait::async_trait]
impl SessionRepo for PgSessionRepo {
    async fn get_by_id(
        &self,
        id: SessionId,
    ) -> Result<Option<Session>, AppError> {
        get_by_id_impl(&self.pool, id).await
    }

    async fn get_by_token_hash(
        &self,
        hash: &[u8; 32],
    ) -> Result<Option<Session>, AppError> {
        get_by_token_hash_impl(&self.pool, hash).await
    }

    async fn get_user_summary(
        &self,
        user_id: UserId,
    ) -> Result<UserSessionSummary, AppError> {
        get_user_summary_impl(&self.pool, user_id).await
    }

    async fn list_admin(
        &self,
        query: &AdminSessionListQuery,
    ) -> Result<PaginatedResult<AdminSessionListItem>, AppError> {
        list_admin_impl(&self.pool, query).await
    }

    async fn get_admin_detail(
        &self,
        id: SessionId,
    ) -> Result<Option<AdminSessionDetailResult>, AppError> {
        get_admin_detail_impl(&self.pool, id).await
    }

    async fn count_active(&self) -> Result<u64, AppError> {
        count_active_impl(&self.pool).await
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

    async fn delete_by_user_id(
        &mut self,
        user_id: UserId,
    ) -> Result<(), AppError> {
        delete_by_user_id_impl(&self.pool, user_id).await
    }
}

#[async_trait::async_trait]
impl SessionRepo for PgTxSessionRepo {
    async fn get_by_id(
        &self,
        id: SessionId,
    ) -> Result<Option<Session>, AppError> {
        get_by_id_impl(self.tx().as_mut(), id).await
    }

    async fn get_by_token_hash(
        &self,
        hash: &[u8; 32],
    ) -> Result<Option<Session>, AppError> {
        get_by_token_hash_impl(self.tx().as_mut(), hash).await
    }

    async fn get_user_summary(
        &self,
        user_id: UserId,
    ) -> Result<UserSessionSummary, AppError> {
        get_user_summary_impl(self.tx().as_mut(), user_id).await
    }

    async fn list_admin(
        &self,
        query: &AdminSessionListQuery,
    ) -> Result<PaginatedResult<AdminSessionListItem>, AppError> {
        let page = query.page.max(1);
        let per_page = query.per_page.clamp(1, 200);
        let offset = i64::from((page - 1) * per_page);
        let limit = i64::from(per_page);

        let total: i64 = build_session_count_query(query)
            .build_query_scalar()
            .fetch_one(self.tx().as_mut())
            .await
            .map_err(infra_error)?;

        let rows = build_session_rows_query(query, limit, offset)
            .build_query_as::<AdminSessionListRow>()
            .fetch_all(self.tx().as_mut())
            .await
            .map_err(infra_error)?;

        Ok(PaginatedResult {
            items: rows.into_iter().map(map_admin_session_list_row).collect(),
            page,
            per_page,
            total: total as u64,
        })
    }

    async fn get_admin_detail(
        &self,
        id: SessionId,
    ) -> Result<Option<AdminSessionDetailResult>, AppError> {
        get_admin_detail_impl(self.tx().as_mut(), id).await
    }

    async fn count_active(&self) -> Result<u64, AppError> {
        count_active_impl(self.tx().as_mut()).await
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

    async fn delete_by_user_id(
        &mut self,
        user_id: UserId,
    ) -> Result<(), AppError> {
        delete_by_user_id_impl(self.tx().as_mut(), user_id).await
    }
}
