use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use aegis_app::{RequestContext, TotpEnrollFinishCommand, TotpVerifyCommand};
use aegis_types::{
    ApiResponse, RecoveryCodesRegenerateRequest, TotpEnrollFinishRequest, TotpVerifyRequest,
};

use crate::auth::RequiredAuth;
use crate::context;
use crate::error::HttpError;
use crate::state::AppState;

pub async fn enroll_totp_start<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    auth: RequiredAuth<R, C, H, T, W, K, I, A>,
    headers: HeaderMap,
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
    let result = state
        .app
        .enroll_totp_start(auth.identity.verified_user_id().map_err(HttpError::from)?)
        .await?;

    Ok(Json(ApiResponse {
        data: Some(serde_json::json!({
            "secret": result.secret,
            "qrCodeUrl": result.qr_code_url,
            "recoveryCodes": result.recovery_codes,
        })),
        error: None,
        meta: aegis_types::ResponseMeta::new(request_id.to_string()),
    }))
}

pub async fn enroll_totp_finish<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    auth: RequiredAuth<R, C, H, T, W, K, I, A>,
    headers: HeaderMap,
    Json(body): Json<TotpEnrollFinishRequest>,
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
    let ctx = RequestContext {
        ip_address: context::extract_ip(&headers),
        user_agent: context::extract_user_agent(&headers),
        request_id: Some(request_id),
    };
    let recovery_codes = state
        .app
        .enroll_totp_finish(
            auth.identity.verified_user_id().map_err(HttpError::from)?,
            TotpEnrollFinishCommand { code: body.code },
            &ctx,
        )
        .await?;

    Ok(Json(ApiResponse {
        data: Some(serde_json::json!({ "recoveryCodes": recovery_codes })),
        error: None,
        meta: aegis_types::ResponseMeta::new(request_id.to_string()),
    }))
}

pub async fn verify_totp<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    auth: RequiredAuth<R, C, H, T, W, K, I, A>,
    headers: HeaderMap,
    Json(body): Json<TotpVerifyRequest>,
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
    let ctx = RequestContext {
        ip_address: context::extract_ip(&headers),
        user_agent: context::extract_user_agent(&headers),
        request_id: Some(request_id),
    };
    let user_id = auth.identity.user_id().map_err(HttpError::from)?;
    state
        .app
        .verify_totp(
            user_id,
            auth.identity.session_token_hash,
            TotpVerifyCommand { code: body.code },
            &ctx,
        )
        .await?;

    Ok(Json(ApiResponse {
        data: Some(serde_json::json!({ "status": "mfa_verified" })),
        error: None,
        meta: aegis_types::ResponseMeta::new(request_id.to_string()),
    }))
}

pub async fn regenerate_recovery_codes<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    auth: RequiredAuth<R, C, H, T, W, K, I, A>,
    headers: HeaderMap,
    _body: Json<RecoveryCodesRegenerateRequest>,
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
    let ctx = RequestContext {
        ip_address: context::extract_ip(&headers),
        user_agent: context::extract_user_agent(&headers),
        request_id: Some(request_id),
    };
    let recovery_codes = state
        .app
        .regenerate_recovery_codes(
            auth.identity.verified_user_id().map_err(HttpError::from)?,
            &ctx,
        )
        .await?;

    Ok(Json(ApiResponse {
        data: Some(serde_json::json!({ "recoveryCodes": recovery_codes })),
        error: None,
        meta: aegis_types::ResponseMeta::new(request_id.to_string()),
    }))
}
