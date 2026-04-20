use serde::{Deserialize, Serialize};

use crate::common::ApiErrorBody;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApiErrorCode {
    AuthInvalidCredentials,
    AuthEmailNotVerified,
    AuthMfaRequired,
    AuthSessionExpired,
    UserNotFound,
    UserAlreadyExists,
    PasswordTooWeak,
    TokenInvalid,
    TokenExpired,
    RateLimited,
    Forbidden,
    InternalError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiErrorResponse {
    pub error: ApiErrorBody,
}

impl ApiErrorResponse {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: ApiErrorBody {
                code: code.into(),
                message: message.into(),
                details: None,
            },
        }
    }

    pub fn with_details(
        code: impl Into<String>,
        message: impl Into<String>,
        details: serde_json::Value,
    ) -> Self {
        Self {
            error: ApiErrorBody {
                code: code.into(),
                message: message.into(),
                details: Some(details),
            },
        }
    }
}
