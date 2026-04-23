use std::ptr::NonNull;

use aegis_app::{AppError, Repos, TransactionRepos};
use sqlx::{PgPool, Postgres, Transaction};

use super::{
    PgAuditRepo, PgCredentialRepo, PgGuestRepo, PgOutboxRepo, PgPendingTokenRepo, PgRoleRepo,
    PgSessionRepo, PgTxAuditRepo, PgTxCredentialRepo, PgTxGuestRepo, PgTxOutboxRepo,
    PgTxPendingTokenRepo, PgTxRoleRepo, PgTxSessionRepo, PgTxUserRepo, PgUserRepo,
};

pub(crate) type TxPtr = NonNull<Transaction<'static, Postgres>>;

fn infra_error(err: impl std::fmt::Display) -> AppError {
    AppError::Infrastructure(err.to_string())
}

pub struct PgRepos {
    users: PgUserRepo,
    guests: PgGuestRepo,
    sessions: PgSessionRepo,
    credentials: PgCredentialRepo,
    roles: PgRoleRepo,
    tokens: PgPendingTokenRepo,
    audit: PgAuditRepo,
    outbox: PgOutboxRepo,
}

impl PgRepos {
    pub fn new(pool: PgPool) -> Self {
        Self {
            users: PgUserRepo::new(pool.clone()),
            guests: PgGuestRepo::new(pool.clone()),
            sessions: PgSessionRepo::new(pool.clone()),
            credentials: PgCredentialRepo::new(pool.clone()),
            roles: PgRoleRepo::new(pool.clone()),
            tokens: PgPendingTokenRepo::new(pool.clone()),
            audit: PgAuditRepo::new(pool.clone()),
            outbox: PgOutboxRepo::new(pool),
        }
    }
}

#[async_trait::async_trait]
impl Repos for PgRepos {
    type Users = PgUserRepo;
    type Guests = PgGuestRepo;
    type Sessions = PgSessionRepo;
    type Credentials = PgCredentialRepo;
    type Roles = PgRoleRepo;
    type Tokens = PgPendingTokenRepo;
    type Audit = PgAuditRepo;
    type Outbox = PgOutboxRepo;
    type Tx = PgTx;

    fn users(&self) -> &Self::Users {
        &self.users
    }

    fn guests(&self) -> &Self::Guests {
        &self.guests
    }

    fn sessions(&self) -> &Self::Sessions {
        &self.sessions
    }

    fn credentials(&self) -> &Self::Credentials {
        &self.credentials
    }

    fn roles(&self) -> &Self::Roles {
        &self.roles
    }

    fn tokens(&self) -> &Self::Tokens {
        &self.tokens
    }

    fn audit(&self) -> &Self::Audit {
        &self.audit
    }

    fn outbox(&self) -> &Self::Outbox {
        &self.outbox
    }

    async fn with_transaction<F, Fut, T>(&self, f: F) -> Result<T, AppError>
    where
        F: FnOnce(Self::Tx) -> Fut + Send,
        Fut: std::future::Future<Output = (Self::Tx, Result<T, AppError>)> + Send,
        T: Send,
    {
        let tx = self
            .users
            .pool()
            .begin()
            .await
            .map_err(infra_error)?;
        let pg_tx = PgTx::new(tx);
        let (pg_tx, result) = f(pg_tx).await;

        match result {
            Ok(value) => {
                pg_tx.tx.commit().await.map_err(infra_error)?;
                Ok(value)
            }
            Err(err) => {
                pg_tx.tx.rollback().await.map_err(infra_error)?;
                Err(err)
            }
        }
    }
}

pub struct PgTx {
    tx: Box<Transaction<'static, Postgres>>,
    users: PgTxUserRepo,
    guests: PgTxGuestRepo,
    sessions: PgTxSessionRepo,
    credentials: PgTxCredentialRepo,
    roles: PgTxRoleRepo,
    tokens: PgTxPendingTokenRepo,
    audit: PgTxAuditRepo,
    outbox: PgTxOutboxRepo,
}

impl PgTx {
    fn new(tx: Transaction<'static, Postgres>) -> Self {
        let mut tx = Box::new(tx);
        let ptr = NonNull::from(tx.as_mut());

        Self {
            users: PgTxUserRepo::new(ptr),
            guests: PgTxGuestRepo::new(ptr),
            sessions: PgTxSessionRepo::new(ptr),
            credentials: PgTxCredentialRepo::new(ptr),
            roles: PgTxRoleRepo::new(ptr),
            tokens: PgTxPendingTokenRepo::new(ptr),
            audit: PgTxAuditRepo::new(ptr),
            outbox: PgTxOutboxRepo::new(ptr),
            tx,
        }
    }
}

impl TransactionRepos for PgTx {
    type Users = PgTxUserRepo;
    type Guests = PgTxGuestRepo;
    type Sessions = PgTxSessionRepo;
    type Credentials = PgTxCredentialRepo;
    type Roles = PgTxRoleRepo;
    type Tokens = PgTxPendingTokenRepo;
    type Audit = PgTxAuditRepo;
    type Outbox = PgTxOutboxRepo;

    fn users(&mut self) -> &mut Self::Users {
        &mut self.users
    }

    fn guests(&mut self) -> &mut Self::Guests {
        &mut self.guests
    }

    fn sessions(&mut self) -> &mut Self::Sessions {
        &mut self.sessions
    }

    fn credentials(&mut self) -> &mut Self::Credentials {
        &mut self.credentials
    }

    fn roles(&mut self) -> &mut Self::Roles {
        &mut self.roles
    }

    fn tokens(&mut self) -> &mut Self::Tokens {
        &mut self.tokens
    }

    fn audit(&mut self) -> &mut Self::Audit {
        &mut self.audit
    }

    fn outbox(&mut self) -> &mut Self::Outbox {
        &mut self.outbox
    }
}
