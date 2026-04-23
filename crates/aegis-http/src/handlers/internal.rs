use axum::extract::State;
use axum::Json;
use aegis_app::{LookupUserByEmailCommand, LookupUserCommand, ValidateSessionCommand};
use aegis_types::{
    ApiResponse, HealthResponse, IdentityLookupResponse, SessionValidateRequest,
    UserLookupByEmailRequest, UserLookupRequest,
};

use crate::error::HttpError;
use crate::state::AppState;

fn format_ts(ts: time::OffsetDateTime) -> String {
    ts.format(&time::format_description::well_known::Iso8601::DEFAULT)
        .unwrap_or_default()
}

pub async fn health<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
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
    let result = state.app.health().await?;
    let value = serde_json::to_value(HealthResponse {
        status: result.status,
        version: result.version,
        database_connected: result.database_connected,
    })
    .unwrap_or_default();

    Ok(Json(ApiResponse {
        data: Some(value),
        error: None,
        meta: aegis_types::ResponseMeta::new(uuid::Uuid::now_v7().to_string()),
    }))
}

pub async fn validate_session<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    Json(body): Json<SessionValidateRequest>,
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
    let token_hash = state.app.deps().tokens.hash_token(&body.token).await;
    let result = state
        .app
        .validate_session(ValidateSessionCommand { token_hash })
        .await?;

    let value = serde_json::json!({
        "valid": result.valid,
        "userId": result.user_id.map(|id| id.to_string()),
        "guestId": result.guest_id.map(|id| id.to_string()),
        "status": result.status,
        "expiresAt": result.expires_at.map(format_ts),
        "roles": result.roles,
        "mfaVerified": result.mfa_verified,
    });

    Ok(Json(ApiResponse {
        data: Some(value),
        error: None,
        meta: aegis_types::ResponseMeta::new(uuid::Uuid::now_v7().to_string()),
    }))
}

pub async fn lookup_user<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    Json(body): Json<UserLookupRequest>,
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
    let result = state
        .app
        .lookup_user(LookupUserCommand { user_id: body.user_id })
        .await?;

    let value = serde_json::to_value(IdentityLookupResponse {
        id: Some(result.id.to_string()),
        email: result.email,
        display_name: result.display_name,
        status: Some(result.status),
        email_verified: result.email_verified,
        roles: result.roles,
        metadata: result
            .metadata
            .and_then(|metadata| serde_json::from_str(&metadata).ok()),
    })
    .unwrap_or_default();

    Ok(Json(ApiResponse {
        data: Some(value),
        error: None,
        meta: aegis_types::ResponseMeta::new(uuid::Uuid::now_v7().to_string()),
    }))
}

pub async fn lookup_user_by_email<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    Json(body): Json<UserLookupByEmailRequest>,
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
    let result = state
        .app
        .lookup_user_by_email(LookupUserByEmailCommand { email: body.email })
        .await?;

    let value = serde_json::to_value(IdentityLookupResponse {
        id: Some(result.id.to_string()),
        email: result.email,
        display_name: result.display_name,
        status: Some(result.status),
        email_verified: result.email_verified,
        roles: result.roles,
        metadata: result
            .metadata
            .and_then(|metadata| serde_json::from_str(&metadata).ok()),
    })
    .unwrap_or_default();

    Ok(Json(ApiResponse {
        data: Some(value),
        error: None,
        meta: aegis_types::ResponseMeta::new(uuid::Uuid::now_v7().to_string()),
    }))
}
