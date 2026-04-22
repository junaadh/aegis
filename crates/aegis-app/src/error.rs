#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("not found: {0}")]
    NotFound(&'static str),

    #[error("validation failed: {0}")]
    Validation(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden")]
    Forbidden,

    #[error("rate limited")]
    RateLimited,

    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("email already exists")]
    EmailAlreadyExists,

    #[error("guest already converted")]
    GuestAlreadyConverted,

    #[error("guest expired")]
    GuestExpired,

    #[error("session expired")]
    SessionExpired,

    #[error("mfa required")]
    MfaRequired,

    #[error("email not verified")]
    EmailNotVerified,

    #[error("password too weak: {0}")]
    PasswordTooWeak(String),

    #[error("token invalid or expired")]
    TokenInvalid,

    #[error("infrastructure failure: {0}")]
    Infrastructure(String),
}
