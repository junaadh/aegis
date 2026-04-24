use aegis_app::{
    ChangePasswordCommand, ForgotPasswordCommand, RequestContext,
    ResendVerificationCommand, ResetPasswordCommand, VerifyEmailCommand,
};
use aegis_types::{
    ApiResponse, ForgotPasswordRequest, PasswordChangeRequest,
    ResetPasswordRequest, VerifyEmailRequest,
};
use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;

use crate::auth::RequiredAuth;
use crate::context;
use crate::cookies;
use crate::error::{ApiJson, HttpError};
use crate::state::AppState;

pub async fn verify_email<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<VerifyEmailRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, HttpError>
where
    R: aegis_app::Repos,
    C: aegis_app::Cache,
    H: aegis_app::Hasher,
    T: aegis_app::TokenGenerator,
    W: aegis_app::WebhookDispatcher,
    K: aegis_app::Clock,
    I: aegis_app::IdGenerator,
    A: aegis_app::WebAuthn,
{
    let request_id = context::extract_or_generate_request_id(&headers);

    let cmd = VerifyEmailCommand { token: body.token };
    state.app.verify_email(cmd).await?;

    let meta = aegis_types::ResponseMeta::new(request_id.to_string());
    Ok(Json(ApiResponse {
        data: Some(serde_json::json!({"status": "email_verified"})),
        error: None,
        meta,
    }))
}

pub async fn resend_verification<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<ResendEmailRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, HttpError>
where
    R: aegis_app::Repos,
    C: aegis_app::Cache,
    H: aegis_app::Hasher,
    T: aegis_app::TokenGenerator,
    W: aegis_app::WebhookDispatcher,
    K: aegis_app::Clock,
    I: aegis_app::IdGenerator,
    A: aegis_app::WebAuthn,
{
    let request_id = context::extract_or_generate_request_id(&headers);

    let cmd = ResendVerificationCommand { email: body.email };
    state.app.resend_verification(cmd).await?;

    let meta = aegis_types::ResponseMeta::new(request_id.to_string());
    Ok(Json(ApiResponse {
        data: Some(serde_json::json!({"status": "verification_sent"})),
        error: None,
        meta,
    }))
}

pub async fn forgot_password<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<ForgotPasswordRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, HttpError>
where
    R: aegis_app::Repos,
    C: aegis_app::Cache,
    H: aegis_app::Hasher,
    T: aegis_app::TokenGenerator,
    W: aegis_app::WebhookDispatcher,
    K: aegis_app::Clock,
    I: aegis_app::IdGenerator,
    A: aegis_app::WebAuthn,
{
    let request_id = context::extract_or_generate_request_id(&headers);

    let cmd = ForgotPasswordCommand { email: body.email };
    state.app.forgot_password(cmd).await?;

    let meta = aegis_types::ResponseMeta::new(request_id.to_string());
    Ok(Json(ApiResponse {
        data: Some(serde_json::json!({"status": "reset_email_sent"})),
        error: None,
        meta,
    }))
}

pub async fn reset_password<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<ResetPasswordRequest>,
) -> Result<(HeaderMap, Json<ApiResponse<serde_json::Value>>), HttpError>
where
    R: aegis_app::Repos,
    C: aegis_app::Cache,
    H: aegis_app::Hasher,
    T: aegis_app::TokenGenerator,
    W: aegis_app::WebhookDispatcher,
    K: aegis_app::Clock,
    I: aegis_app::IdGenerator,
    A: aegis_app::WebAuthn,
{
    let request_id = context::extract_or_generate_request_id(&headers);

    let cmd = ResetPasswordCommand {
        token: body.token,
        new_password: body.new_password,
    };
    state.app.reset_password(cmd).await?;

    let mut response_headers = HeaderMap::new();
    cookies::clear_session_cookie(
        &mut response_headers,
        &state
            .config
            .session
            .as_ref()
            .expect("session config is required")
            .cookie,
    );

    let meta = aegis_types::ResponseMeta::new(request_id.to_string());
    Ok((
        response_headers,
        Json(ApiResponse {
            data: Some(serde_json::json!({"status": "password_reset"})),
            error: None,
            meta,
        }),
    ))
}

pub async fn change_password<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    auth: RequiredAuth<R, C, H, T, W, K, I, A>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<PasswordChangeRequest>,
) -> Result<(HeaderMap, Json<ApiResponse<serde_json::Value>>), HttpError>
where
    R: aegis_app::Repos,
    C: aegis_app::Cache,
    H: aegis_app::Hasher,
    T: aegis_app::TokenGenerator,
    W: aegis_app::WebhookDispatcher,
    K: aegis_app::Clock,
    I: aegis_app::IdGenerator,
    A: aegis_app::WebAuthn,
{
    let identity = auth.identity;
    let user_id = identity.verified_user_id().map_err(HttpError::from)?;

    let request_id = context::extract_or_generate_request_id(&headers);
    let ctx = RequestContext {
        ip_address: context::extract_ip(&headers),
        user_agent: context::extract_user_agent(&headers),
        request_id: Some(request_id),
    };

    let cmd = ChangePasswordCommand {
        current_password: body.current_password,
        new_password: body.new_password,
    };
    state.app.change_password(user_id, cmd, &ctx).await?;

    let mut response_headers = HeaderMap::new();
    cookies::clear_session_cookie(
        &mut response_headers,
        &state
            .config
            .session
            .as_ref()
            .expect("session config is required")
            .cookie,
    );

    let meta = aegis_types::ResponseMeta::new(request_id.to_string());
    Ok((
        response_headers,
        Json(ApiResponse {
            data: Some(serde_json::json!({"status": "password_changed"})),
            error: None,
            meta,
        }),
    ))
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResendEmailRequest {
    pub email: String,
}
