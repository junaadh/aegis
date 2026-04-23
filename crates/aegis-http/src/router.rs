use axum::Router;
use axum::routing::{get, patch, post};

use crate::handlers;
use crate::state::AppState;

fn auth_routes<R, C, H, T, W, K, I, A>() -> Router<AppState<R, C, H, T, W, K, I, A>>
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

fn mfa_routes<R, C, H, T, W, K, I, A>() -> Router<AppState<R, C, H, T, W, K, I, A>>
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
        .route("/totp/enroll", post(handlers::enroll_totp_start).put(handlers::enroll_totp_finish))
        .route("/totp/verify", post(handlers::verify_totp))
        .route(
            "/totp/recovery-codes/regenerate",
            post(handlers::regenerate_recovery_codes),
        )
}

fn session_routes<R, C, H, T, W, K, I, A>() -> Router<AppState<R, C, H, T, W, K, I, A>>
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

fn guest_routes<R, C, H, T, W, K, I, A>() -> Router<AppState<R, C, H, T, W, K, I, A>>
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

fn email_routes<R, C, H, T, W, K, I, A>() -> Router<AppState<R, C, H, T, W, K, I, A>>
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

fn password_routes<R, C, H, T, W, K, I, A>() -> Router<AppState<R, C, H, T, W, K, I, A>>
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

fn passkey_routes<R, C, H, T, W, K, I, A>() -> Router<AppState<R, C, H, T, W, K, I, A>>
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

fn internal_routes<R, C, H, T, W, K, I, A>() -> Router<AppState<R, C, H, T, W, K, I, A>>
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
        .route("/session/validate", post(handlers::validate_session))
        .route("/user/lookup", post(handlers::lookup_user))
        .route("/user/lookup-by-email", post(handlers::lookup_user_by_email))
}

pub fn v1_router<R, C, H, T, W, K, I, A>() -> Router<AppState<R, C, H, T, W, K, I, A>>
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

pub fn app_router<R, C, H, T, W, K, I, A>() -> Router<AppState<R, C, H, T, W, K, I, A>>
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
    Router::new().nest("/v1", v1_router::<R, C, H, T, W, K, I, A>())
}
