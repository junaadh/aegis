use std::path::Path;

use aegis_config::Config;

fn main() {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "aegis.toml".to_owned());

    let config = match Config::load(Some(Path::new(&config_path))) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to load config from {config_path}: {e}");
            std::process::exit(1);
        }
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(async move { run(config).await });
}

async fn run(config: Config) {
    let bind_addr = format!("{}:{}", config.server.host, config.server.port);

    tracing::info!("aegisd starting on {bind_addr}");

    let listener = match tokio::net::TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("failed to bind to {bind_addr}: {e}");
            std::process::exit(1);
        }
    };

    tracing::info!(
        "aegisd listening on {bind_addr} — NOTE: no database wired yet, handler stubs only"
    );

    let app = axum::Router::new().fallback(|| async {
        axum::http::StatusCode::NOT_FOUND
    });

    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        tracing::error!("server error: {e}");
    }
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install ctrl-c handler");
    tracing::info!("shutdown signal received");
}
