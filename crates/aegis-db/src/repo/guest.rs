use aegis_app::{
    AdminGuestDetailResult, AdminGuestListItem, AdminGuestListQuery, AppError,
    GuestRepo, PaginatedResult,
};
use aegis_core::Guest;
use sqlx::{Executor, FromRow, PgPool, Postgres, QueryBuilder, Transaction};

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

fn map_guest(row: GuestRow) -> Result<Guest, AppError> {
    row.try_into().map_err(infra_error)
}

async fn get_by_id_impl<'e, E>(
    executor: E,
    id: aegis_core::GuestId,
) -> Result<Option<Guest>, AppError>
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

#[derive(Debug, FromRow)]
struct AdminGuestListRow {
    id: uuid::Uuid,
    email: Option<String>,
    converted_to: Option<uuid::Uuid>,
    expires_at: time::OffsetDateTime,
    created_at: time::OffsetDateTime,
    updated_at: time::OffsetDateTime,
}

fn compute_guest_status(
    converted_to: Option<uuid::Uuid>,
    expires_at: time::OffsetDateTime,
) -> String {
    if converted_to.is_some() {
        "converted".to_owned()
    } else if expires_at <= time::OffsetDateTime::now_utc() {
        "expired".to_owned()
    } else {
        "active".to_owned()
    }
}

fn map_admin_guest_list_row(row: AdminGuestListRow) -> AdminGuestListItem {
    AdminGuestListItem {
        id: row.id,
        email: row.email,
        status: compute_guest_status(row.converted_to, row.expires_at),
        converted_to: row.converted_to,
        expires_at: row.expires_at,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

fn push_guest_status_filter(
    builder: &mut QueryBuilder<'_, Postgres>,
    status: &str,
) {
    match status {
        "active" => {
            builder.push(" AND g.converted_to IS NULL AND g.expires_at > NOW()");
        }
        "converted" => {
            builder.push(" AND g.converted_to IS NOT NULL");
        }
        "expired" => {
            builder.push(" AND g.converted_to IS NULL AND g.expires_at <= NOW()");
        }
        _ => {}
    }
}

fn build_guest_count_query(
    query: &AdminGuestListQuery,
) -> QueryBuilder<'static, Postgres> {
    let mut builder =
        QueryBuilder::<Postgres>::new("SELECT COUNT(*) FROM guests g WHERE 1 = 1");
    if let Some(status) = query.status.as_deref() {
        push_guest_status_filter(&mut builder, status);
    }
    builder
}

fn build_guest_rows_query(
    query: &AdminGuestListQuery,
    limit: i64,
    offset: i64,
) -> QueryBuilder<'static, Postgres> {
    let sort = match query.sort.as_deref().unwrap_or("created_at") {
        "updated_at" => "g.updated_at",
        "expires_at" => "g.expires_at",
        _ => "g.created_at",
    };
    let order = match query.order.as_deref().unwrap_or("desc") {
        "asc" => "ASC",
        _ => "DESC",
    };

    let mut builder = QueryBuilder::<Postgres>::new(
        "SELECT g.id, g.email, g.converted_to, g.expires_at, g.created_at, g.updated_at FROM guests g WHERE 1 = 1",
    );
    if let Some(status) = query.status.as_deref() {
        push_guest_status_filter(&mut builder, status);
    }
    builder.push(" ORDER BY ");
    builder.push(sort);
    builder.push(" ");
    builder.push(order);
    builder.push(", g.id ASC LIMIT ");
    builder.push_bind(limit);
    builder.push(" OFFSET ");
    builder.push_bind(offset);
    builder
}

async fn list_admin_impl<'e, E>(
    executor: E,
    query: &AdminGuestListQuery,
) -> Result<PaginatedResult<AdminGuestListItem>, AppError>
where
    E: Executor<'e, Database = Postgres> + Copy,
{
    let page = query.page.max(1);
    let per_page = query.per_page.clamp(1, 200);
    let offset = i64::from((page - 1) * per_page);
    let limit = i64::from(per_page);

    let total: i64 = build_guest_count_query(query)
        .build_query_scalar()
        .fetch_one(executor)
        .await
        .map_err(infra_error)?;

    let rows = build_guest_rows_query(query, limit, offset)
        .build_query_as::<AdminGuestListRow>()
        .fetch_all(executor)
        .await
        .map_err(infra_error)?;

    Ok(PaginatedResult {
        items: rows.into_iter().map(map_admin_guest_list_row).collect(),
        page,
        per_page,
        total: total as u64,
    })
}

async fn get_admin_detail_impl<'e, E>(
    executor: E,
    id: aegis_core::GuestId,
) -> Result<Option<AdminGuestDetailResult>, AppError>
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

    row.map(|row| {
        let status = compute_guest_status(row.converted_to, row.expires_at);
        Ok(AdminGuestDetailResult {
            id: row.id,
            email: row.email,
            status,
            converted_to: row.converted_to,
            metadata: row.metadata,
            expires_at: row.expires_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    })
    .transpose()
}

async fn count_impl<'e, E>(executor: E) -> Result<u64, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM guests")
            .fetch_one(executor)
            .await
            .map_err(infra_error)?;

    Ok(count as u64)
}

async fn count_active_impl<'e, E>(executor: E) -> Result<u64, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM guests WHERE converted_to IS NULL AND expires_at > NOW()",
    )
    .fetch_one(executor)
    .await
    .map_err(infra_error)?;

    Ok(count as u64)
}

#[async_trait::async_trait]
impl GuestRepo for PgGuestRepo {
    async fn get_by_id(
        &self,
        id: aegis_core::GuestId,
    ) -> Result<Option<Guest>, AppError> {
        get_by_id_impl(&self.pool, id).await
    }

    async fn list_admin(
        &self,
        query: &AdminGuestListQuery,
    ) -> Result<PaginatedResult<AdminGuestListItem>, AppError> {
        list_admin_impl(&self.pool, query).await
    }

    async fn get_admin_detail(
        &self,
        id: aegis_core::GuestId,
    ) -> Result<Option<AdminGuestDetailResult>, AppError> {
        get_admin_detail_impl(&self.pool, id).await
    }

    async fn count(&self) -> Result<u64, AppError> {
        count_impl(&self.pool).await
    }

    async fn count_active(&self) -> Result<u64, AppError> {
        count_active_impl(&self.pool).await
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
    async fn get_by_id(
        &self,
        id: aegis_core::GuestId,
    ) -> Result<Option<Guest>, AppError> {
        get_by_id_impl(self.tx().as_mut(), id).await
    }

    async fn list_admin(
        &self,
        query: &AdminGuestListQuery,
    ) -> Result<PaginatedResult<AdminGuestListItem>, AppError> {
        let page = query.page.max(1);
        let per_page = query.per_page.clamp(1, 200);
        let offset = i64::from((page - 1) * per_page);
        let limit = i64::from(per_page);

        let total: i64 = build_guest_count_query(query)
            .build_query_scalar()
            .fetch_one(self.tx().as_mut())
            .await
            .map_err(infra_error)?;

        let rows = build_guest_rows_query(query, limit, offset)
            .build_query_as::<AdminGuestListRow>()
            .fetch_all(self.tx().as_mut())
            .await
            .map_err(infra_error)?;

        Ok(PaginatedResult {
            items: rows.into_iter().map(map_admin_guest_list_row).collect(),
            page,
            per_page,
            total: total as u64,
        })
    }

    async fn get_admin_detail(
        &self,
        id: aegis_core::GuestId,
    ) -> Result<Option<AdminGuestDetailResult>, AppError> {
        get_admin_detail_impl(self.tx().as_mut(), id).await
    }

    async fn count(&self) -> Result<u64, AppError> {
        count_impl(self.tx().as_mut()).await
    }

    async fn count_active(&self) -> Result<u64, AppError> {
        count_active_impl(self.tx().as_mut()).await
    }

    async fn insert(&mut self, guest: &Guest) -> Result<(), AppError> {
        insert_impl(self.tx().as_mut(), guest).await
    }

    async fn update(&mut self, guest: &Guest) -> Result<(), AppError> {
        update_impl(self.tx().as_mut(), guest).await
    }
}
