use aegis_app::{RequestContext, SessionRevokeCommand};
use aegis_types::{ApiResponse, SessionRevokeRequest};
use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;

use crate::auth::RequiredAuth;
use crate::context;
use crate::error::{ApiJson, HttpError};
use crate::state::AppState;

pub async fn revoke_session<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    auth: RequiredAuth<R, C, H, T, W, K, I, A>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<SessionRevokeRequest>,
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

    state
        .app
        .revoke_session(
            auth.identity.verified_user_id().map_err(HttpError::from)?,
            SessionRevokeCommand {
                session_id: body.session_id,
            },
            &ctx,
        )
        .await?;

    Ok(Json(ApiResponse {
        data: Some(serde_json::json!({ "status": "session_revoked" })),
        error: None,
        meta: aegis_types::ResponseMeta::new(request_id.to_string()),
    }))
}

pub async fn revoke_all_sessions<R, C, H, T, W, K, I, A>(
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
    let ctx = RequestContext {
        ip_address: context::extract_ip(&headers),
        user_agent: context::extract_user_agent(&headers),
        request_id: Some(request_id),
    };

    state
        .app
        .revoke_all_sessions(
            auth.identity.verified_user_id().map_err(HttpError::from)?,
            Some(auth.identity.session_token_hash),
            &ctx,
        )
        .await?;

    Ok(Json(ApiResponse {
        data: Some(serde_json::json!({ "status": "sessions_revoked" })),
        error: None,
        meta: aegis_types::ResponseMeta::new(request_id.to_string()),
    }))
}
