use aegis_app::{
    AdminUserListItem, AdminUserListQuery, AppError, PaginatedResult, UserRepo,
};
use aegis_core::User;
use sqlx::{Executor, FromRow, PgPool, Postgres, QueryBuilder, Transaction};

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

fn map_user(row: UserRow) -> Result<User, AppError> {
    row.try_into().map_err(infra_error)
}

#[derive(Debug, FromRow)]
struct AdminUserListRow {
    id: uuid::Uuid,
    email: String,
    display_name: String,
    status: String,
    email_verified_at: Option<time::OffsetDateTime>,
    created_at: time::OffsetDateTime,
    updated_at: time::OffsetDateTime,
}

fn map_admin_user_list_row(row: AdminUserListRow) -> AdminUserListItem {
    AdminUserListItem {
        id: row.id,
        email: row.email,
        display_name: row.display_name,
        status: row.status,
        email_verified: row.email_verified_at.is_some(),
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

fn push_admin_user_filters(
    builder: &mut QueryBuilder<'_, Postgres>,
    query: &AdminUserListQuery,
) {
    if let Some(status) = query.status.clone().filter(|value| !value.is_empty())
    {
        builder.push(" AND u.status = ");
        builder.push_bind(status);
    }

    if let Some(verified) = query.verified {
        if verified {
            builder.push(" AND u.email_verified_at IS NOT NULL");
        } else {
            builder.push(" AND u.email_verified_at IS NULL");
        }
    }

    if let Some(role) = query.role.clone().filter(|value| !value.is_empty()) {
        builder.push(
            " AND EXISTS (SELECT 1 FROM user_role_assignments ura INNER JOIN roles r ON r.id = ura.role_id WHERE ura.user_id = u.id AND (ura.expires_at IS NULL OR ura.expires_at > NOW()) AND r.name = ",
        );
        builder.push_bind(role);
        builder.push(")");
    }

    if let Some(search) = query.q.clone().filter(|value| !value.is_empty()) {
        let pattern = format!("{}%", search.to_lowercase());
        builder.push(" AND (LOWER(u.email) LIKE ");
        builder.push_bind(pattern.clone());
        builder.push(" OR LOWER(u.display_name) LIKE ");
        builder.push_bind(pattern);
        builder.push(")");
    }
}

fn build_admin_user_count_query(
    query: &AdminUserListQuery,
) -> QueryBuilder<'static, Postgres> {
    let mut builder = QueryBuilder::<Postgres>::new(
        "SELECT COUNT(*) FROM users u WHERE 1 = 1",
    );
    push_admin_user_filters(&mut builder, query);
    builder
}

fn build_admin_user_rows_query(
    query: &AdminUserListQuery,
    limit: i64,
    offset: i64,
) -> QueryBuilder<'static, Postgres> {
    let sort = match query.sort.as_deref().unwrap_or("created_at") {
        "email" => "u.email",
        "updated_at" => "u.updated_at",
        _ => "u.created_at",
    };
    let order = match query.order.as_deref().unwrap_or("desc") {
        "asc" => "ASC",
        _ => "DESC",
    };

    let mut builder = QueryBuilder::<Postgres>::new(
        "SELECT u.id, u.email, u.display_name, u.status, u.email_verified_at, u.created_at, u.updated_at FROM users u WHERE 1 = 1",
    );
    push_admin_user_filters(&mut builder, query);
    builder.push(" ORDER BY ");
    builder.push(sort);
    builder.push(" ");
    builder.push(order);
    builder.push(", u.id ASC LIMIT ");
    builder.push_bind(limit);
    builder.push(" OFFSET ");
    builder.push_bind(offset);
    builder
}

async fn list_admin_impl<'e, E>(
    executor: E,
    query: &AdminUserListQuery,
) -> Result<PaginatedResult<AdminUserListItem>, AppError>
where
    E: Executor<'e, Database = Postgres> + Copy,
{
    let page = query.page.max(1);
    let per_page = query.per_page.clamp(1, 200);
    let offset = i64::from((page - 1) * per_page);
    let limit = i64::from(per_page);

    let total: i64 = build_admin_user_count_query(query)
        .build_query_scalar()
        .fetch_one(executor)
        .await
        .map_err(infra_error)?;

    let rows = build_admin_user_rows_query(query, limit, offset)
        .build_query_as::<AdminUserListRow>()
        .fetch_all(executor)
        .await
        .map_err(infra_error)?;

    Ok(PaginatedResult {
        items: rows.into_iter().map(map_admin_user_list_row).collect(),
        page,
        per_page,
        total: total as u64,
    })
}

async fn get_by_id_impl<'e, E>(
    executor: E,
    id: aegis_core::UserId,
) -> Result<Option<User>, AppError>
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

async fn get_by_email_impl<'e, E>(
    executor: E,
    email: &str,
) -> Result<Option<User>, AppError>
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

async fn email_exists_impl<'e, E>(
    executor: E,
    email: &str,
) -> Result<bool, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM users WHERE LOWER(email) = LOWER($1))",
    )
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

async fn count_impl<'e, E>(executor: E) -> Result<u64, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE status != 'deleted'",
    )
    .fetch_one(executor)
    .await
    .map_err(infra_error)?;

    Ok(count as u64)
}

async fn count_by_status_impl<'e, E>(
    executor: E,
    status: &str,
) -> Result<u64, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE status = $1",
    )
    .bind(status)
    .fetch_one(executor)
    .await
    .map_err(infra_error)?;

    Ok(count as u64)
}

#[async_trait::async_trait]
impl UserRepo for PgUserRepo {
    async fn get_by_id(
        &self,
        id: aegis_core::UserId,
    ) -> Result<Option<User>, AppError> {
        get_by_id_impl(&self.pool, id).await
    }

    async fn get_by_email(
        &self,
        email: &str,
    ) -> Result<Option<User>, AppError> {
        get_by_email_impl(&self.pool, email).await
    }

    async fn list_admin(
        &self,
        query: &AdminUserListQuery,
    ) -> Result<PaginatedResult<AdminUserListItem>, AppError> {
        list_admin_impl(&self.pool, query).await
    }

    async fn email_exists(&self, email: &str) -> Result<bool, AppError> {
        email_exists_impl(&self.pool, email).await
    }

    async fn count(&self) -> Result<u64, AppError> {
        count_impl(&self.pool).await
    }

    async fn count_by_status(&self, status: &str) -> Result<u64, AppError> {
        count_by_status_impl(&self.pool, status).await
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
    async fn get_by_id(
        &self,
        id: aegis_core::UserId,
    ) -> Result<Option<User>, AppError> {
        get_by_id_impl(self.tx().as_mut(), id).await
    }

    async fn get_by_email(
        &self,
        email: &str,
    ) -> Result<Option<User>, AppError> {
        get_by_email_impl(self.tx().as_mut(), email).await
    }

    async fn list_admin(
        &self,
        query: &AdminUserListQuery,
    ) -> Result<PaginatedResult<AdminUserListItem>, AppError> {
        let page = query.page.max(1);
        let per_page = query.per_page.clamp(1, 200);
        let offset = i64::from((page - 1) * per_page);
        let limit = i64::from(per_page);

        let total: i64 = build_admin_user_count_query(query)
            .build_query_scalar()
            .fetch_one(self.tx().as_mut())
            .await
            .map_err(infra_error)?;

        let rows = build_admin_user_rows_query(query, limit, offset)
            .build_query_as::<AdminUserListRow>()
            .fetch_all(self.tx().as_mut())
            .await
            .map_err(infra_error)?;

        Ok(PaginatedResult {
            items: rows.into_iter().map(map_admin_user_list_row).collect(),
            page,
            per_page,
            total: total as u64,
        })
    }

    async fn email_exists(&self, email: &str) -> Result<bool, AppError> {
        email_exists_impl(self.tx().as_mut(), email).await
    }

    async fn count(&self) -> Result<u64, AppError> {
        count_impl(self.tx().as_mut()).await
    }

    async fn count_by_status(&self, status: &str) -> Result<u64, AppError> {
        count_by_status_impl(self.tx().as_mut(), status).await
    }

    async fn insert(&mut self, user: &User) -> Result<(), AppError> {
        insert_impl(self.tx().as_mut(), user).await
    }

    async fn update(&mut self, user: &User) -> Result<(), AppError> {
        update_impl(self.tx().as_mut(), user).await
    }
}
