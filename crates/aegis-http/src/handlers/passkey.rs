use aegis_app::RequestContext;
use aegis_types::ApiResponse;
use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;

use crate::auth::RequiredAuth;
use crate::context;
use crate::cookies;
use crate::error::{ApiJson, HttpError};
use crate::mapping;
use crate::state::AppState;

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyRegisterFinishRequest {
    #[serde(with = "base64_bytes")]
    pub response: Vec<u8>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyLoginFinishRequest {
    pub user_id: String,
    #[serde(with = "base64_bytes")]
    pub response: Vec<u8>,
}

mod base64_bytes {
    use base64::Engine;
    use serde::{self, Deserialize, Deserializer};

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(&s)
            .map_err(serde::de::Error::custom)
    }
}

pub async fn passkey_register_start<R, C, H, T, W, K, I, A>(
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
    let user_id = auth.identity.verified_user_id().map_err(HttpError::from)?;

    let public_key = state.app.passkey_register_start(user_id).await?;

    Ok(Json(ApiResponse {
        data: Some(public_key),
        error: None,
        meta: aegis_types::ResponseMeta::new(request_id.to_string()),
    }))
}

pub async fn passkey_register_finish<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    auth: RequiredAuth<R, C, H, T, W, K, I, A>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<PasskeyRegisterFinishRequest>,
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
    let user_id = auth.identity.verified_user_id().map_err(HttpError::from)?;

    state
        .app
        .passkey_register_finish(user_id, body.response, &ctx)
        .await?;

    Ok(Json(ApiResponse {
        data: Some(serde_json::json!({"status": "passkey_registered"})),
        error: None,
        meta: aegis_types::ResponseMeta::new(request_id.to_string()),
    }))
}

pub async fn passkey_login_start<R, C, H, T, W, K, I, A>(
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
    let user_id = auth.identity.verified_user_id().map_err(HttpError::from)?;

    let public_key = state.app.passkey_login_start(user_id).await?;

    Ok(Json(ApiResponse {
        data: Some(public_key),
        error: None,
        meta: aegis_types::ResponseMeta::new(request_id.to_string()),
    }))
}

pub async fn passkey_login_finish<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<PasskeyLoginFinishRequest>,
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
    let ctx = RequestContext {
        ip_address: context::extract_ip(&headers),
        user_agent: context::extract_user_agent(&headers),
        request_id: Some(request_id),
    };

    let user_id = uuid::Uuid::parse_str(&body.user_id).map_err(|_| {
        HttpError::from(aegis_app::AppError::Validation(
            "invalid user_id".to_owned(),
        ))
    })?;
    let user_id = aegis_core::UserId::from_uuid(user_id);

    let result = state
        .app
        .passkey_login_finish(user_id, body.response, &ctx)
        .await?;

    let mut response_headers = HeaderMap::new();
    cookies::set_session_cookie(
        &mut response_headers,
        &state
            .config
            .session
            .as_ref()
            .expect("session config is required")
            .cookie,
        &result.session_token,
        state.app.policy().auth.session_max_age,
    );

    let mapped = mapping::map_auth_result(&result);
    let meta = aegis_types::ResponseMeta::new(request_id.to_string());
    let value = serde_json::to_value(mapped).unwrap_or_default();

    Ok((
        response_headers,
        Json(ApiResponse {
            data: Some(value),
            error: None,
            meta,
        }),
    ))
}
