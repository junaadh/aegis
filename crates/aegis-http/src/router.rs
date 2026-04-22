use axum::Router;
use axum::routing::{get, patch, post};

use crate::handlers;
use crate::state::AppState;

fn auth_routes<R, C, H, T, W, K, I>() -> Router<AppState<R, C, H, T, W, K, I>>
where
    R: aegis_app::Repos + Clone + 'static,
    C: aegis_app::Cache + Clone + 'static,
    H: aegis_app::Hasher + Clone + 'static,
    T: aegis_app::TokenGenerator + Clone + 'static,
    W: aegis_app::WebhookDispatcher + Clone + 'static,
    K: aegis_app::Clock + Clone + 'static,
    I: aegis_app::IdGenerator + Clone + 'static,
{
    Router::new()
        .route("/signup", post(handlers::signup))
        .route("/login", post(handlers::login))
        .route("/logout", post(handlers::logout))
        .route("/me", get(handlers::me).patch(handlers::update_profile))
        .nest("/guest", guest_routes::<R, C, H, T, W, K, I>())
        .nest("/email", email_routes::<R, C, H, T, W, K, I>())
        .nest("/password", password_routes::<R, C, H, T, W, K, I>())
}

fn guest_routes<R, C, H, T, W, K, I>() -> Router<AppState<R, C, H, T, W, K, I>>
where
    R: aegis_app::Repos + Clone + 'static,
    C: aegis_app::Cache + Clone + 'static,
    H: aegis_app::Hasher + Clone + 'static,
    T: aegis_app::TokenGenerator + Clone + 'static,
    W: aegis_app::WebhookDispatcher + Clone + 'static,
    K: aegis_app::Clock + Clone + 'static,
    I: aegis_app::IdGenerator + Clone + 'static,
{
    Router::new()
        .route("/", post(handlers::create_guest))
        .route("/email", patch(handlers::associate_guest_email))
        .route("/convert", post(handlers::convert_guest))
}

fn email_routes<R, C, H, T, W, K, I>() -> Router<AppState<R, C, H, T, W, K, I>>
where
    R: aegis_app::Repos + Clone + 'static,
    C: aegis_app::Cache + Clone + 'static,
    H: aegis_app::Hasher + Clone + 'static,
    T: aegis_app::TokenGenerator + Clone + 'static,
    W: aegis_app::WebhookDispatcher + Clone + 'static,
    K: aegis_app::Clock + Clone + 'static,
    I: aegis_app::IdGenerator + Clone + 'static,
{
    Router::new()
        .route("/verify", post(handlers::verify_email))
        .route("/resend", post(handlers::resend_verification))
}

fn password_routes<R, C, H, T, W, K, I>() -> Router<AppState<R, C, H, T, W, K, I>>
where
    R: aegis_app::Repos + Clone + 'static,
    C: aegis_app::Cache + Clone + 'static,
    H: aegis_app::Hasher + Clone + 'static,
    T: aegis_app::TokenGenerator + Clone + 'static,
    W: aegis_app::WebhookDispatcher + Clone + 'static,
    K: aegis_app::Clock + Clone + 'static,
    I: aegis_app::IdGenerator + Clone + 'static,
{
    Router::new()
        .route("/forgot", post(handlers::forgot_password))
        .route("/reset", post(handlers::reset_password))
        .route("/change", post(handlers::change_password))
}

pub fn v1_router<R, C, H, T, W, K, I>() -> Router<AppState<R, C, H, T, W, K, I>>
where
    R: aegis_app::Repos + Clone + 'static,
    C: aegis_app::Cache + Clone + 'static,
    H: aegis_app::Hasher + Clone + 'static,
    T: aegis_app::TokenGenerator + Clone + 'static,
    W: aegis_app::WebhookDispatcher + Clone + 'static,
    K: aegis_app::Clock + Clone + 'static,
    I: aegis_app::IdGenerator + Clone + 'static,
{
    Router::new().nest("/auth", auth_routes::<R, C, H, T, W, K, I>())
}

pub fn app_router<R, C, H, T, W, K, I>() -> Router<AppState<R, C, H, T, W, K, I>>
where
    R: aegis_app::Repos + Clone + 'static,
    C: aegis_app::Cache + Clone + 'static,
    H: aegis_app::Hasher + Clone + 'static,
    T: aegis_app::TokenGenerator + Clone + 'static,
    W: aegis_app::WebhookDispatcher + Clone + 'static,
    K: aegis_app::Clock + Clone + 'static,
    I: aegis_app::IdGenerator + Clone + 'static,
{
    Router::new().nest("/v1", v1_router::<R, C, H, T, W, K, I>())
}
