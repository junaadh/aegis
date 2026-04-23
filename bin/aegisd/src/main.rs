use std::path::Path;
use std::sync::Arc;

use aegis_app::{
    AppDeps, AppPolicies, EmailSender, OutboxEntry, OutboxRepo, Repos, TransactionRepos,
};
use aegis_config::Config;
use aegis_db::repo::PgRepos;
use aegis_http::{
    app_router, request_id_middleware, AppHandle, AppState,
};
use axum::extract::State;
use aegis_infra::{
    Argon2Hasher, ConfiguredCache, NoopWebhookDispatcher, SmtpEmailSender, SystemClock,
    SystemTokenGenerator, UuidV7IdGenerator,
};
use axum::middleware;
use axum::response::Response;
use axum::{body::Body, http::Request};
use serde::Deserialize;
use sqlx::postgres::PgPoolOptions;
use time::{Duration, OffsetDateTime};
use tower_http::cors::CorsLayer;

#[tokio::main]
async fn main() {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "aegis.toml".to_owned());

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = match Config::load(Some(Path::new(&config_path))) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("failed to load config from {config_path}: {err}");
            std::process::exit(1);
        }
    };

    if let Err(err) = run(config).await {
        tracing::error!(error = %err, "aegisd failed");
        std::process::exit(1);
    }
}

async fn run(config: Config) -> Result<(), String> {
    let db = config
        .database
        .as_ref()
        .ok_or_else(|| "database config is required".to_owned())?;

    let pool = PgPoolOptions::new()
        .max_connections(db.max_connections)
        .min_connections(db.min_idle)
        .acquire_timeout(std::time::Duration::from_secs(db.connection_timeout_seconds))
        .connect(&db.url)
        .await
        .map_err(|e| format!("failed to connect to postgres: {e}"))?;

    let repos = PgRepos::new(pool.clone());
    let hasher = Argon2Hasher::from_config(&config).map_err(app_error)?;
    let tokens = SystemTokenGenerator::new();
    let cache = ConfiguredCache::from_config(&config).map_err(app_error)?;
    let clock = SystemClock::new();
    let ids = UuidV7IdGenerator::new();
    let webhooks = NoopWebhookDispatcher::new();
    let policies = AppPolicies::from_config(&config).map_err(app_error)?;

    let app = aegis_app::AegisApp::new(
        AppDeps {
            repos,
            cache,
            hasher,
            tokens,
            webhooks,
            clock,
            ids,
        },
        policies,
    );

    let state = Arc::new(AppHandle {
        app,
        config: config.clone(),
    });

    if config.email.enabled {
        let email_sender = SmtpEmailSender::from_config(&config).map_err(app_error)?;
        tokio::spawn(run_outbox_worker(PgRepos::new(pool.clone()), email_sender));
    }

    let bind_addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .map_err(|e| format!("failed to bind to {bind_addr}: {e}"))?;

    tracing::info!(bind_addr, "aegisd listening");

    let app = app_router::<
        PgRepos,
        ConfiguredCache,
        Argon2Hasher,
        SystemTokenGenerator,
        NoopWebhookDispatcher,
        SystemClock,
        UuidV7IdGenerator,
    >()
    .with_state(state.clone())
    .layer(CorsLayer::permissive())
    .layer(middleware::from_fn(request_id_middleware))
    .layer(middleware::from_fn_with_state(
        state.clone(),
        auth_context_middleware_for_server,
    ))
    .layer(middleware::from_fn_with_state(
        state.clone(),
        internal_auth_middleware_for_server,
    ));

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| format!("server error: {e}"))
}

type ServerState = AppState<
    PgRepos,
    ConfiguredCache,
    Argon2Hasher,
    SystemTokenGenerator,
    NoopWebhookDispatcher,
    SystemClock,
    UuidV7IdGenerator,
>;

async fn auth_context_middleware_for_server(
    State(state): State<ServerState>,
    request: Request<Body>,
    next: middleware::Next,
) -> Response {
    aegis_http::auth_context_middleware(state, request, next).await
}

async fn internal_auth_middleware_for_server(
    State(state): State<ServerState>,
    request: Request<Body>,
    next: middleware::Next,
) -> Response {
    aegis_http::internal_auth_middleware(state, request, next).await
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install ctrl-c handler");
    tracing::info!("shutdown signal received");
}

fn app_error(err: aegis_app::AppError) -> String {
    err.to_string()
}

#[derive(Deserialize)]
struct VerificationEmailPayload {
    email: String,
    token: String,
}

#[derive(Deserialize)]
struct PasswordResetEmailPayload {
    email: String,
    token: String,
}

async fn run_outbox_worker(repos: PgRepos, email: SmtpEmailSender) {
    let mut interval = tokio::time::interval(std::time::Duration::from_millis(500));

    loop {
        interval.tick().await;

        let entries = match repos
            .with_transaction(|mut tx| async move {
                let result = tx.outbox().claim_pending(10).await;
                (tx, result)
            })
            .await
        {
            Ok(entries) => entries,
            Err(err) => {
                tracing::error!(error = %err, "failed to claim outbox jobs");
                continue;
            }
        };

        for entry in entries {
            process_outbox_entry(&repos, &email, entry).await;
        }
    }
}

async fn process_outbox_entry(repos: &PgRepos, email: &SmtpEmailSender, entry: OutboxEntry) {
    let result = match entry.job_type.as_str() {
        "send_verification_email" => {
            let payload: Result<VerificationEmailPayload, _> = serde_json::from_str(&entry.payload);
            match payload {
                Ok(payload) => email.send_verification(&payload.email, &payload.token).await,
                Err(err) => Err(aegis_app::AppError::Infrastructure(format!(
                    "invalid verification outbox payload: {err}"
                ))),
            }
        }
        "send_password_reset_email" => {
            let payload: Result<PasswordResetEmailPayload, _> = serde_json::from_str(&entry.payload);
            match payload {
                Ok(payload) => email.send_password_reset(&payload.email, &payload.token).await,
                Err(err) => Err(aegis_app::AppError::Infrastructure(format!(
                    "invalid password reset outbox payload: {err}"
                ))),
            }
        }
        other => {
            tracing::warn!(job_type = other, "unsupported outbox job type");
            Ok(())
        }
    };

    let repo_result = match result {
        Ok(()) => {
            repos.with_transaction(|mut tx| async move {
                let result = tx.outbox().mark_processed(entry.id).await;
                (tx, result)
            })
            .await
        }
        Err(err) => {
            tracing::error!(job_id = entry.id, error = %err, "outbox job failed");
            let attempts = entry.attempts + 1;
            if attempts >= entry.max_attempts {
                repos.with_transaction(|mut tx| async move {
                    let result = tx.outbox().mark_dead_lettered(entry.id).await;
                    (tx, result)
                })
                .await
            } else {
                let next_retry_at = OffsetDateTime::now_utc() + Duration::minutes(1);
                repos.with_transaction(|mut tx| async move {
                    let result = tx.outbox().mark_retry(entry.id, next_retry_at).await;
                    (tx, result)
                })
                .await
            }
        }
    };

    if let Err(err) = repo_result {
        tracing::error!(job_id = entry.id, error = %err, "failed to update outbox job status");
    }
}
