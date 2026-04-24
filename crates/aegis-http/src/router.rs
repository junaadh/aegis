use axum::Router;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};

use crate::handlers;
use crate::state::AppState;
use crate::{context, error::HttpError};

async fn not_found(headers: HeaderMap) -> Response {
    HttpError::with_status(
        StatusCode::NOT_FOUND,
        aegis_types::ApiErrorCode::InternalError,
        "not found",
        context::extract_or_generate_request_id(&headers).to_string(),
    )
    .into_response()
}

async fn method_not_allowed(headers: HeaderMap) -> Response {
    HttpError::with_status(
        StatusCode::METHOD_NOT_ALLOWED,
        aegis_types::ApiErrorCode::InternalError,
        "method not allowed",
        context::extract_or_generate_request_id(&headers).to_string(),
    )
    .into_response()
}

fn auth_routes<R, C, H, T, W, K, I, A>()
-> Router<AppState<R, C, H, T, W, K, I, A>>
where
    R: aegis_app::Repos + 'static,
    C: aegis_app::Cache + 'static,
    H: aegis_app::Hasher + 'static,
    T: aegis_app::TokenGenerator + 'static,
    W: aegis_app::WebhookDispatcher + 'static,
    K: aegis_app::Clock + 'static,
    I: aegis_app::IdGenerator + 'static,
    A: aegis_app::WebAuthn + 'static,
{
    Router::new()
        .route("/signup", post(handlers::signup))
        .route("/login", post(handlers::login))
        .route("/logout", post(handlers::logout))
        .route("/me", get(handlers::me).patch(handlers::update_profile))
        .nest("/mfa", mfa_routes::<R, C, H, T, W, K, I, A>())
        .nest("/session", session_routes::<R, C, H, T, W, K, I, A>())
        .nest("/guest", guest_routes::<R, C, H, T, W, K, I, A>())
        .nest("/email", email_routes::<R, C, H, T, W, K, I, A>())
        .nest("/password", password_routes::<R, C, H, T, W, K, I, A>())
        .nest("/passkey", passkey_routes::<R, C, H, T, W, K, I, A>())
}

fn mfa_routes<R, C, H, T, W, K, I, A>()
-> Router<AppState<R, C, H, T, W, K, I, A>>
where
    R: aegis_app::Repos + 'static,
    C: aegis_app::Cache + 'static,
    H: aegis_app::Hasher + 'static,
    T: aegis_app::TokenGenerator + 'static,
    W: aegis_app::WebhookDispatcher + 'static,
    K: aegis_app::Clock + 'static,
    I: aegis_app::IdGenerator + 'static,
    A: aegis_app::WebAuthn + 'static,
{
    Router::new()
        .route(
            "/totp/enroll",
            post(handlers::enroll_totp_start).put(handlers::enroll_totp_finish),
        )
        .route("/totp/verify", post(handlers::verify_totp))
        .route(
            "/totp/recovery-codes/regenerate",
            post(handlers::regenerate_recovery_codes),
        )
}

fn session_routes<R, C, H, T, W, K, I, A>()
-> Router<AppState<R, C, H, T, W, K, I, A>>
where
    R: aegis_app::Repos + 'static,
    C: aegis_app::Cache + 'static,
    H: aegis_app::Hasher + 'static,
    T: aegis_app::TokenGenerator + 'static,
    W: aegis_app::WebhookDispatcher + 'static,
    K: aegis_app::Clock + 'static,
    I: aegis_app::IdGenerator + 'static,
    A: aegis_app::WebAuthn + 'static,
{
    Router::new()
        .route("/revoke", post(handlers::revoke_session))
        .route("/revoke-all", post(handlers::revoke_all_sessions))
}

fn guest_routes<R, C, H, T, W, K, I, A>()
-> Router<AppState<R, C, H, T, W, K, I, A>>
where
    R: aegis_app::Repos + 'static,
    C: aegis_app::Cache + 'static,
    H: aegis_app::Hasher + 'static,
    T: aegis_app::TokenGenerator + 'static,
    W: aegis_app::WebhookDispatcher + 'static,
    K: aegis_app::Clock + 'static,
    I: aegis_app::IdGenerator + 'static,
    A: aegis_app::WebAuthn + 'static,
{
    Router::new()
        .route("/", post(handlers::create_guest))
        .route("/email", patch(handlers::associate_guest_email))
        .route("/convert", post(handlers::convert_guest))
}

fn email_routes<R, C, H, T, W, K, I, A>()
-> Router<AppState<R, C, H, T, W, K, I, A>>
where
    R: aegis_app::Repos + 'static,
    C: aegis_app::Cache + 'static,
    H: aegis_app::Hasher + 'static,
    T: aegis_app::TokenGenerator + 'static,
    W: aegis_app::WebhookDispatcher + 'static,
    K: aegis_app::Clock + 'static,
    I: aegis_app::IdGenerator + 'static,
    A: aegis_app::WebAuthn + 'static,
{
    Router::new()
        .route("/verify", post(handlers::verify_email))
        .route("/resend", post(handlers::resend_verification))
}

fn password_routes<R, C, H, T, W, K, I, A>()
-> Router<AppState<R, C, H, T, W, K, I, A>>
where
    R: aegis_app::Repos + 'static,
    C: aegis_app::Cache + 'static,
    H: aegis_app::Hasher + 'static,
    T: aegis_app::TokenGenerator + 'static,
    W: aegis_app::WebhookDispatcher + 'static,
    K: aegis_app::Clock + 'static,
    I: aegis_app::IdGenerator + 'static,
    A: aegis_app::WebAuthn + 'static,
{
    Router::new()
        .route("/forgot", post(handlers::forgot_password))
        .route("/reset", post(handlers::reset_password))
        .route("/change", post(handlers::change_password))
}

fn passkey_routes<R, C, H, T, W, K, I, A>()
-> Router<AppState<R, C, H, T, W, K, I, A>>
where
    R: aegis_app::Repos + 'static,
    C: aegis_app::Cache + 'static,
    H: aegis_app::Hasher + 'static,
    T: aegis_app::TokenGenerator + 'static,
    W: aegis_app::WebhookDispatcher + 'static,
    K: aegis_app::Clock + 'static,
    I: aegis_app::IdGenerator + 'static,
    A: aegis_app::WebAuthn + 'static,
{
    Router::new()
        .route("/register/start", post(handlers::passkey_register_start))
        .route("/register/finish", post(handlers::passkey_register_finish))
        .route("/login/start", post(handlers::passkey_login_start))
        .route("/login/finish", post(handlers::passkey_login_finish))
}

fn internal_routes<R, C, H, T, W, K, I, A>()
-> Router<AppState<R, C, H, T, W, K, I, A>>
where
    R: aegis_app::Repos + 'static,
    C: aegis_app::Cache + 'static,
    H: aegis_app::Hasher + 'static,
    T: aegis_app::TokenGenerator + 'static,
    W: aegis_app::WebhookDispatcher + 'static,
    K: aegis_app::Clock + 'static,
    I: aegis_app::IdGenerator + 'static,
    A: aegis_app::WebAuthn + 'static,
{
    Router::new()
        .route("/health", get(handlers::health))
        .route("/overview", get(handlers::overview))
        .route("/session/validate", post(handlers::validate_session))
        .route("/sessions/validate", post(handlers::validate_session))
        .route("/user/lookup", post(handlers::lookup_user))
        .route(
            "/user/lookup-by-email",
            post(handlers::lookup_user_by_email),
        )
        .route("/users", get(handlers::list_admin_users))
        .route("/users/lookup", get(handlers::lookup_user_by_email_query))
        .route("/users/{id}", get(handlers::admin_user_detail))
        .route("/users/{id}/roles", get(handlers::admin_user_roles))
        .route("/users/{id}/disable", post(handlers::admin_disable_user))
        .route("/users/{id}/enable", post(handlers::admin_enable_user))
        .route(
            "/users/{id}/revoke-sessions",
            post(handlers::admin_revoke_user_sessions),
        )
        .route("/guests", get(handlers::list_admin_guests))
        .route("/guests/{id}", get(handlers::admin_guest_detail))
        .route("/sessions", get(handlers::list_admin_sessions))
        .route("/sessions/{id}", get(handlers::admin_session_detail))
        .route(
            "/sessions/{id}/revoke",
            post(handlers::admin_revoke_session),
        )
}

pub fn v1_router<R, C, H, T, W, K, I, A>()
-> Router<AppState<R, C, H, T, W, K, I, A>>
where
    R: aegis_app::Repos + 'static,
    C: aegis_app::Cache + 'static,
    H: aegis_app::Hasher + 'static,
    T: aegis_app::TokenGenerator + 'static,
    W: aegis_app::WebhookDispatcher + 'static,
    K: aegis_app::Clock + 'static,
    I: aegis_app::IdGenerator + 'static,
    A: aegis_app::WebAuthn + 'static,
{
    Router::new()
        .nest("/auth", auth_routes::<R, C, H, T, W, K, I, A>())
        .nest("/internal", internal_routes::<R, C, H, T, W, K, I, A>())
}

pub fn app_router<R, C, H, T, W, K, I, A>()
-> Router<AppState<R, C, H, T, W, K, I, A>>
where
    R: aegis_app::Repos + 'static,
    C: aegis_app::Cache + 'static,
    H: aegis_app::Hasher + 'static,
    T: aegis_app::TokenGenerator + 'static,
    W: aegis_app::WebhookDispatcher + 'static,
    K: aegis_app::Clock + 'static,
    I: aegis_app::IdGenerator + 'static,
    A: aegis_app::WebAuthn + 'static,
{
    Router::new()
        .nest("/v1", v1_router::<R, C, H, T, W, K, I, A>())
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
}
