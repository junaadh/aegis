use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use aegis_app::{AppDeps, AppPolicies};
use aegis_config::Config;
use aegis_db::outbox::OutboxWorker;
use aegis_db::repo::PgRepos;
use aegis_http::{AppHandle, AppState, app_router, request_id_middleware};
use aegis_infra::{
    Argon2Hasher, ConfiguredCache, EmailOutboxProcessor, JwtVerifier,
    NoopWebhookDispatcher, SmtpEmailSender, SystemClock, SystemTokenGenerator,
    UuidV7IdGenerator, WebAuthnAdapter,
};
use axum::extract::State;
use axum::middleware;
use axum::response::Response;
use axum::{body::Body, http::Request};
use ipnet::IpNet;
use sqlx::postgres::PgPoolOptions;
use tower_http::cors::CorsLayer;

#[tokio::main]
async fn main() {
    let config_path = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("AEGIS_CONFIG").ok())
        .unwrap_or_else(|| "aegis.toml".to_owned());

    let config = match Config::load(Some(Path::new(&config_path))) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("failed to load config from {config_path}: {err}");
            std::process::exit(1);
        }
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| {
                    tracing_subscriber::EnvFilter::new(config.server.log_level)
                }),
        )
        .init();

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
        .acquire_timeout(std::time::Duration::from_secs(
            db.connection_timeout_seconds,
        ))
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
    let internal_allowed_cidrs = parse_internal_allowed_cidrs(&config)?;
    let internal_jwt_verifier =
        JwtVerifier::from_config(&config).map_err(|e| e.to_string())?;

    let webauthn = match WebAuthnAdapter::from_config(
        &config.credentials.passkeys,
    ) {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!(error = %e, "passkeys disabled: webauthn not configured");
            return Err(format!("webauthn config error: {e}"))?;
        }
    };

    let app = aegis_app::AegisApp::new(
        AppDeps {
            repos,
            cache,
            hasher,
            tokens,
            webhooks,
            clock,
            ids,
            webauthn,
        },
        policies,
    );

    let state = Arc::new(AppHandle {
        app,
        config: config.clone(),
        internal_allowed_cidrs: Arc::new(internal_allowed_cidrs),
        internal_jwt_verifier: internal_jwt_verifier.map(Arc::new),
        started_at: std::time::Instant::now(),
    });

    if config.email.enabled {
        let email_sender =
            SmtpEmailSender::from_config(&config).map_err(app_error)?;
        let processor = EmailOutboxProcessor::new(email_sender);
        let worker = OutboxWorker::new(
            pool.clone(),
            PgRepos::new(pool.clone()),
            processor,
        );
        tokio::spawn(worker.run());
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
        WebAuthnAdapter,
    >()
    .with_state(state.clone())
    .layer(CorsLayer::permissive())
    .layer(middleware::from_fn_with_state(
        state.clone(),
        auth_context_middleware_for_server,
    ))
    .layer(middleware::from_fn_with_state(
        state.clone(),
        internal_auth_middleware_for_server,
    ))
    .layer(middleware::from_fn_with_state(
        state.clone(),
        internal_network_guard_for_server,
    ));

    let app = app.layer(middleware::from_fn(request_id_middleware));

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
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
    WebAuthnAdapter,
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

async fn internal_network_guard_for_server(
    State(state): State<ServerState>,
    request: Request<Body>,
    next: middleware::Next,
) -> Response {
    aegis_http::internal_network_guard(state, request, next).await
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

fn parse_internal_allowed_cidrs(config: &Config) -> Result<Vec<IpNet>, String> {
    config
        .api
        .internal
        .allowed_cidrs
        .iter()
        .map(|cidr| {
            cidr.parse::<IpNet>().map_err(|err| {
                format!(
                    "invalid api.internal.allowed_cidrs entry '{cidr}': {err}"
                )
            })
        })
        .collect()
}
