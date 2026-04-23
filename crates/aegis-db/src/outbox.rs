use aegis_app::{OutboxEntry, OutboxProcessor, OutboxRepo, Repos, TransactionRepos};
use sqlx::postgres::PgListener;
use sqlx::PgPool;
use time::OffsetDateTime;

const CHANNEL: &str = "aegis_outbox";
const CLAIM_BATCH: usize = 16;
const FALLBACK_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
const BASE_RETRY_DELAY_SECS: i64 = 5;

pub struct OutboxWorker<R, P>
where
    R: Repos,
    P: OutboxProcessor,
{
    repos: R,
    processor: P,
    pool: PgPool,
}

impl<R, P> OutboxWorker<R, P>
where
    R: Repos,
    P: OutboxProcessor,
{
    pub fn new(pool: PgPool, repos: R, processor: P) -> Self {
        Self { repos, processor, pool }
    }

    pub async fn run(self) {
        let mut listener = match PgListener::connect_with(&self.pool).await {
            Ok(mut l) => {
                if let Err(e) = l.listen(CHANNEL).await {
                    tracing::warn!(error = %e, "failed to LISTEN on {CHANNEL}, falling back to poll");
                }
                Some(l)
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to create PgListener, falling back to poll");
                None
            }
        };

        self.drain().await;

        loop {
            if let Some(ref mut l) = listener {
                let mut timeout = tokio::time::interval(FALLBACK_POLL_INTERVAL);
                timeout.tick().await;
                loop {
                    tokio::select! {
                        result = l.recv() => {
                            match result {
                                Ok(_) => break,
                                Err(e) => {
                                    tracing::error!(error = %e, "pg_listener recv error");
                                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                                    let _ = l.listen(CHANNEL).await;
                                    continue;
                                }
                            }
                        }
                        _ = timeout.tick() => break,
                    }
                }
            } else {
                tokio::time::sleep(FALLBACK_POLL_INTERVAL).await;
            }

            self.drain().await;
        }
    }

    async fn drain(&self) {
        loop {
            let entries = match self.claim().await {
                Ok(entries) => entries,
                Err(e) => {
                    tracing::error!(error = %e, "failed to claim outbox jobs");
                    return;
                }
            };

            if entries.is_empty() {
                return;
            }

            for entry in entries {
                self.process_entry(entry).await;
            }
        }
    }

    async fn claim(&self) -> Result<Vec<OutboxEntry>, aegis_app::AppError> {
        self.repos
            .with_transaction(|mut tx| async move {
                let result = tx.outbox().claim_pending(CLAIM_BATCH).await;
                (tx, result)
            })
            .await
    }

    async fn process_entry(&self, entry: OutboxEntry) {
        let id = entry.id;
        let result = self
            .processor
            .process(&entry.job_type, &entry.payload)
            .await;

        match result {
            Ok(()) => {
                if let Err(e) = self.mark_processed(id).await {
                    tracing::error!(job_id = id, error = %e, "failed to mark processed");
                }
            }
            Err(err) => {
                tracing::error!(job_id = id, error = %err, "outbox job failed");
                if let Err(e) = self.handle_failure(entry).await {
                    tracing::error!(job_id = id, error = %e, "failed to update failed job");
                }
            }
        }
    }

    async fn handle_failure(&self, entry: OutboxEntry) -> Result<(), aegis_app::AppError> {
        let next_attempt = entry.attempts + 1;
        if next_attempt >= entry.max_attempts {
            self.mark_dead_lettered(entry.id).await
        } else {
            let delay_secs = BASE_RETRY_DELAY_SECS * 2i64.pow(next_attempt);
            let next_retry_at = OffsetDateTime::now_utc() + time::Duration::seconds(delay_secs);
            self.mark_retry(entry.id, next_retry_at).await
        }
    }

    async fn mark_processed(&self, id: i64) -> Result<(), aegis_app::AppError> {
        self.repos
            .with_transaction(|mut tx| async move {
                let result = tx.outbox().mark_processed(id).await;
                (tx, result)
            })
            .await
    }

    async fn mark_retry(
        &self,
        id: i64,
        next_retry_at: OffsetDateTime,
    ) -> Result<(), aegis_app::AppError> {
        self.repos
            .with_transaction(|mut tx| async move {
                let result = tx.outbox().mark_retry(id, next_retry_at).await;
                (tx, result)
            })
            .await
    }

    async fn mark_dead_lettered(&self, id: i64) -> Result<(), aegis_app::AppError> {
        self.repos
            .with_transaction(|mut tx| async move {
                let result = tx.outbox().mark_dead_lettered(id).await;
                (tx, result)
            })
            .await
    }
}
