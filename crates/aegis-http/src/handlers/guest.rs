use aegis_app::{
    CreateGuestCommand, GuestConvertCommand, GuestEmailCommand, RequestContext,
};
use aegis_types::{
    ApiResponse, GuestConvertRequest, GuestCreateRequest, GuestEmailRequest,
};
use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;

use crate::auth::{OptionalAuth, RequiredAuth};
use crate::context;
use crate::cookies;
use crate::error::{ApiJson, HttpError};
use crate::mapping;
use crate::state::AppState;

pub async fn create_guest<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    auth: OptionalAuth<R, C, H, T, W, K, I, A>,
    headers: HeaderMap,
    _body: ApiJson<GuestCreateRequest>,
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
    let existing_auth = auth.identity;

    let request_id = context::extract_or_generate_request_id(&headers);
    let ctx = RequestContext {
        ip_address: context::extract_ip(&headers),
        user_agent: context::extract_user_agent(&headers),
        request_id: Some(request_id),
    };

    let result = state.app.create_guest(CreateGuestCommand, &ctx).await?;

    let mut response_headers = HeaderMap::new();
    if existing_auth.is_some() {
        tracing::warn!(
            request_id = %request_id,
            "guest create called with existing session, replacing"
        );
    }
    cookies::set_session_cookie(
        &mut response_headers,
        &state
            .config
            .session
            .as_ref()
            .expect("session config is required")
            .cookie,
        &result.session_token,
        state.app.policy().compliance.guest_ttl,
    );

    let mapped = mapping::map_guest_auth_result(&result);
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

pub async fn associate_guest_email<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    auth: RequiredAuth<R, C, H, T, W, K, I, A>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<GuestEmailRequest>,
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
    let identity = auth.identity;
    let guest_id = identity.guest_id().map_err(HttpError::from)?;

    let request_id = context::extract_or_generate_request_id(&headers);
    let ctx = RequestContext {
        ip_address: context::extract_ip(&headers),
        user_agent: context::extract_user_agent(&headers),
        request_id: Some(request_id),
    };

    let cmd = GuestEmailCommand { email: body.email };
    state.app.associate_guest_email(guest_id, cmd, &ctx).await?;

    let meta = aegis_types::ResponseMeta::new(request_id.to_string());
    Ok(Json(ApiResponse {
        data: Some(serde_json::json!({"status": "email_associated"})),
        error: None,
        meta,
    }))
}

pub async fn convert_guest<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    auth: RequiredAuth<R, C, H, T, W, K, I, A>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<GuestConvertRequest>,
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
    let guest_id = identity.guest_id().map_err(HttpError::from)?;

    let request_id = context::extract_or_generate_request_id(&headers);
    let ctx = RequestContext {
        ip_address: context::extract_ip(&headers),
        user_agent: context::extract_user_agent(&headers),
        request_id: Some(request_id),
    };

    let cmd = GuestConvertCommand {
        email: body.email,
        password: body.password,
        display_name: body.display_name,
    };

    let result = state.app.convert_guest(guest_id, cmd, &ctx).await?;

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
