use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use aegis_app::AppError;
use aegis_types::{ApiErrorBody, ApiErrorCode, ApiErrorResponse};

pub struct HttpError(pub AppError);

impl From<AppError> for HttpError {
    fn from(err: AppError) -> Self {
        Self(err)
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self.0 {
            AppError::NotFound(what) => (
                StatusCode::NOT_FOUND,
                ApiErrorCode::UserNotFound,
                format!("{what} not found"),
            ),
            AppError::Validation(msg) => (
                StatusCode::BAD_REQUEST,
                ApiErrorCode::InternalError,
                msg.clone(),
            ),
            AppError::Conflict(msg) => (
                StatusCode::CONFLICT,
                ApiErrorCode::UserAlreadyExists,
                msg.clone(),
            ),
            AppError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                ApiErrorCode::AuthInvalidCredentials,
                "unauthorized".to_owned(),
            ),
            AppError::Forbidden => (
                StatusCode::FORBIDDEN,
                ApiErrorCode::Forbidden,
                "forbidden".to_owned(),
            ),
            AppError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                ApiErrorCode::RateLimited,
                "rate limited".to_owned(),
            ),
            AppError::InvalidCredentials => (
                StatusCode::UNAUTHORIZED,
                ApiErrorCode::AuthInvalidCredentials,
                "invalid credentials".to_owned(),
            ),
            AppError::EmailAlreadyExists => (
                StatusCode::CONFLICT,
                ApiErrorCode::UserAlreadyExists,
                "email already exists".to_owned(),
            ),
            AppError::GuestAlreadyConverted => (
                StatusCode::CONFLICT,
                ApiErrorCode::UserAlreadyExists,
                "guest already converted".to_owned(),
            ),
            AppError::GuestExpired => (
                StatusCode::BAD_REQUEST,
                ApiErrorCode::TokenExpired,
                "guest expired".to_owned(),
            ),
            AppError::SessionExpired => (
                StatusCode::UNAUTHORIZED,
                ApiErrorCode::AuthSessionExpired,
                "session expired".to_owned(),
            ),
            AppError::MfaRequired => (
                StatusCode::UNAUTHORIZED,
                ApiErrorCode::AuthMfaRequired,
                "mfa required".to_owned(),
            ),
            AppError::EmailNotVerified => (
                StatusCode::FORBIDDEN,
                ApiErrorCode::AuthEmailNotVerified,
                "email not verified".to_owned(),
            ),
            AppError::PasswordTooWeak(msg) => (
                StatusCode::BAD_REQUEST,
                ApiErrorCode::PasswordTooWeak,
                msg.clone(),
            ),
            AppError::TokenInvalid => (
                StatusCode::BAD_REQUEST,
                ApiErrorCode::TokenInvalid,
                "token invalid or expired".to_owned(),
            ),
            AppError::Infrastructure(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ApiErrorCode::InternalError,
                msg.clone(),
            ),
        };

        let body = ApiErrorResponse {
            error: ApiErrorBody {
                code: serde_json::to_value(&code)
                    .ok()
                    .and_then(|v| v.as_str().map(|s| s.to_owned()))
                    .unwrap_or_default(),
                message,
                details: None,
            },
        };

        (status, axum::Json(body)).into_response()
    }
}
