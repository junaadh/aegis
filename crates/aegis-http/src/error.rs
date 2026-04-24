use aegis_app::AppError;
use aegis_types::{ApiErrorBody, ApiErrorCode, ApiResponse, ResponseMeta};
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use serde::de::DeserializeOwned;

use crate::context;

pub struct HttpError {
    status: StatusCode,
    code: ApiErrorCode,
    message: String,
    details: Option<serde_json::Value>,
    request_id: String,
}

pub struct ApiJson<T>(pub T);
pub struct ApiQuery<T>(pub T);

impl<T> std::ops::Deref for ApiJson<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> std::ops::DerefMut for ApiJson<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> std::ops::Deref for ApiQuery<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T, S> FromRequest<S> for ApiJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = HttpError;

    fn from_request(
        req: Request,
        state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send
    {
        let request_id =
            context::extract_or_generate_request_id(req.headers()).to_string();

        async move {
            let axum::Json(value) = axum::Json::<T>::from_request(req, state)
                .await
                .map_err(|rejection| {
                    HttpError::from_json_rejection(rejection, request_id)
                })?;
            Ok(Self(value))
        }
    }
}

impl<T, S> FromRequestParts<S> for ApiQuery<T>
where
    T: DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = HttpError;

    fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send
    {
        let request_id =
            context::extract_or_generate_request_id(&parts.headers).to_string();

        async move {
            let axum::extract::Query(value) =
                axum::extract::Query::<T>::from_request_parts(parts, state)
                    .await
                    .map_err(|rejection| {
                        HttpError::from_query_rejection(rejection, request_id)
                    })?;
            Ok(Self(value))
        }
    }
}

impl From<AppError> for HttpError {
    fn from(err: AppError) -> Self {
        Self::from_app_error(err, uuid::Uuid::now_v7().to_string())
    }
}

impl HttpError {
    pub fn from_app_error(err: AppError, request_id: String) -> Self {
        let (status, code, message) = match err {
            AppError::NotFound(what) => (
                StatusCode::NOT_FOUND,
                ApiErrorCode::UserNotFound,
                format!("{what} not found"),
            ),
            AppError::Validation(msg) => {
                (StatusCode::BAD_REQUEST, ApiErrorCode::InternalError, msg)
            }
            AppError::Conflict(msg) => {
                (StatusCode::CONFLICT, ApiErrorCode::UserAlreadyExists, msg)
            }
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
            AppError::PasswordTooWeak(msg) => {
                (StatusCode::BAD_REQUEST, ApiErrorCode::PasswordTooWeak, msg)
            }
            AppError::TokenInvalid => (
                StatusCode::BAD_REQUEST,
                ApiErrorCode::TokenInvalid,
                "token invalid or expired".to_owned(),
            ),
            AppError::Infrastructure(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ApiErrorCode::InternalError,
                msg,
            ),
        };

        Self {
            status,
            code,
            message,
            details: None,
            request_id,
        }
    }

    pub fn with_status(
        status: StatusCode,
        code: ApiErrorCode,
        message: impl Into<String>,
        request_id: String,
    ) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            details: None,
            request_id,
        }
    }

    pub fn from_json_rejection(
        rejection: JsonRejection,
        request_id: String,
    ) -> Self {
        let status = rejection.status();
        let message = rejection.body_text();
        Self {
            status,
            code: ApiErrorCode::InternalError,
            message,
            details: None,
            request_id,
        }
    }

    pub fn from_query_rejection(
        rejection: QueryRejection,
        request_id: String,
    ) -> Self {
        Self {
            status: rejection.status(),
            code: ApiErrorCode::InternalError,
            message: rejection.body_text(),
            details: None,
            request_id,
        }
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let body = ApiResponse::<serde_json::Value> {
            data: None,
            error: Some(ApiErrorBody {
                code: serde_json::to_value(&self.code)
                    .ok()
                    .and_then(|v| v.as_str().map(|s| s.to_owned()))
                    .unwrap_or_default(),
                message: self.message,
                details: self.details,
            }),
            meta: ResponseMeta::new(self.request_id),
        };

        (self.status, axum::Json(body)).into_response()
    }
}
