use aegis_app::{AppError, RoleRepo};
use aegis_core::{Role, UserId, UserRoleAssignment};
use sqlx::{Executor, PgPool, Postgres, Transaction};

use crate::repo::pg_repos::TxPtr;
use crate::row::{RoleRow, UserRoleAssignmentRow};

pub struct PgRoleRepo {
    pool: PgPool,
}

impl PgRoleRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

pub struct PgTxRoleRepo {
    tx: TxPtr,
}

unsafe impl Send for PgTxRoleRepo {}
unsafe impl Sync for PgTxRoleRepo {}

impl PgTxRoleRepo {
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

async fn get_roles_by_user_id_impl<'e, E>(
    executor: E,
    user_id: UserId,
) -> Result<Vec<Role>, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let rows = sqlx::query_as::<_, RoleRow>(
        "SELECT r.id, r.name, r.description, r.permissions, r.created_at, r.updated_at
         FROM roles r
         INNER JOIN user_role_assignments ura ON ura.role_id = r.id
         WHERE ura.user_id = $1 AND (ura.expires_at IS NULL OR ura.expires_at > NOW())
         ORDER BY r.created_at",
    )
    .bind(user_id.as_uuid())
    .fetch_all(executor)
    .await
    .map_err(infra_error)?;

    rows.into_iter()
        .map(|row| Role::try_from(row).map_err(infra_error))
        .collect()
}

async fn get_assignments_by_user_id_impl<'e, E>(
    executor: E,
    user_id: UserId,
) -> Result<Vec<UserRoleAssignment>, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let rows = sqlx::query_as::<_, UserRoleAssignmentRow>(
        "SELECT id, user_id, role_id, granted_by, granted_at, expires_at FROM user_role_assignments WHERE user_id = $1 ORDER BY granted_at",
    )
    .bind(user_id.as_uuid())
    .fetch_all(executor)
    .await
    .map_err(infra_error)?;

    Ok(rows.into_iter().map(Into::into).collect())
}

#[async_trait::async_trait]
impl RoleRepo for PgRoleRepo {
    async fn get_roles_by_user_id(
        &self,
        user_id: UserId,
    ) -> Result<Vec<Role>, AppError> {
        get_roles_by_user_id_impl(&self.pool, user_id).await
    }

    async fn get_assignments_by_user_id(
        &self,
        user_id: UserId,
    ) -> Result<Vec<UserRoleAssignment>, AppError> {
        get_assignments_by_user_id_impl(&self.pool, user_id).await
    }
}

#[async_trait::async_trait]
impl RoleRepo for PgTxRoleRepo {
    async fn get_roles_by_user_id(
        &self,
        user_id: UserId,
    ) -> Result<Vec<Role>, AppError> {
        get_roles_by_user_id_impl(self.tx().as_mut(), user_id).await
    }

    async fn get_assignments_by_user_id(
        &self,
        user_id: UserId,
    ) -> Result<Vec<UserRoleAssignment>, AppError> {
        get_assignments_by_user_id_impl(self.tx().as_mut(), user_id).await
    }
}
