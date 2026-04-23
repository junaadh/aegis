use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use aegis_app::{LoginCommand, RequestContext, SignupCommand};
use aegis_types::{ApiResponse, LoginRequest, SignupRequest};

use crate::auth::{OptionalAuth, RequiredAuth};
use crate::context;
use crate::cookies;
use crate::error::HttpError;
use crate::mapping;
use crate::state::AppState;

pub async fn signup<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    auth: OptionalAuth<R, C, H, T, W, K, I, A>,
    headers: HeaderMap,
    Json(body): Json<SignupRequest>,
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

    let cmd = SignupCommand {
        email: body.email,
        password: body.password,
        display_name: body.display_name,
    };

    let result = state.app.signup(cmd, &ctx).await?;

    let mut response_headers = HeaderMap::new();
    if existing_auth.is_some() {
        tracing::warn!(
            request_id = %request_id,
            "signup called with existing session, replacing"
        );
    }
    cookies::set_session_cookie(
        &mut response_headers,
        &state.config.session.as_ref().expect("session config is required").cookie,
        &result.session_token,
        state.app.policy().auth.session_max_age,
    );

    let auth_response = mapping::map_auth_result(&result);
    let meta = aegis_types::ResponseMeta::new(request_id.to_string());
    let value = serde_json::to_value(auth_response).unwrap_or_default();

    Ok((
        response_headers,
        Json(ApiResponse {
            data: Some(value),
            error: None,
            meta,
        }),
    ))
}

pub async fn login<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
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

    let cmd = LoginCommand {
        email: body.email,
        password: body.password,
    };

    let outcome = state.app.login_with_password(cmd, &ctx).await?;

    let mut response_headers = HeaderMap::new();

    match &outcome {
        aegis_app::LoginOutcome::Authenticated(result) => {
            cookies::set_session_cookie(
                &mut response_headers,
                &state.config.session.as_ref().expect("session config is required").cookie,
                &result.session_token,
                state.app.policy().auth.session_max_age,
            );
        }
        aegis_app::LoginOutcome::RequiresMfa { session_token, .. } => {
            cookies::set_session_cookie(
                &mut response_headers,
                &state.config.session.as_ref().expect("session config is required").cookie,
                session_token,
                state.app.policy().auth.session_max_age,
            );
        }
    }

    let mapped = mapping::map_login_outcome(&outcome);
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

pub async fn logout<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    auth: RequiredAuth<R, C, H, T, W, K, I, A>,
    headers: HeaderMap,
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

    let request_id = context::extract_or_generate_request_id(&headers);
    let ctx = RequestContext {
        ip_address: context::extract_ip(&headers),
        user_agent: context::extract_user_agent(&headers),
        request_id: Some(request_id),
    };

    let cmd = aegis_app::LogoutCommand {
        session_token_hash: identity.session_token_hash,
    };

    state.app.logout(cmd, &ctx).await?;

    let mut response_headers = HeaderMap::new();
    cookies::clear_session_cookie(
        &mut response_headers,
        &state.config.session.as_ref().expect("session config is required").cookie,
    );

    let meta = aegis_types::ResponseMeta::new(request_id.to_string());
    Ok((
        response_headers,
        Json(ApiResponse {
            data: Some(serde_json::json!({"status": "logged_out"})),
            error: None,
            meta,
        }),
    ))
}

pub async fn me<R, C, H, T, W, K, I, A>(
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
    let identity = auth.identity;

    let request_id = context::extract_or_generate_request_id(&headers);

    let result = match &identity.inner {
        aegis_core::Identity::User(_) => {
            state.app.get_current_identity(identity.verified_user_id()?).await?
        }
        aegis_core::Identity::Guest(g) => {
            state.app.get_guest_identity(g.id).await?
        }
    };

    let mapped = mapping::map_identity_result(&result);
    let meta = aegis_types::ResponseMeta::new(request_id.to_string());
    let value = serde_json::to_value(mapped).unwrap_or_default();

    Ok(Json(ApiResponse {
        data: Some(value),
        error: None,
        meta,
    }))
}

pub async fn update_profile<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    auth: RequiredAuth<R, C, H, T, W, K, I, A>,
    headers: HeaderMap,
    Json(body): Json<aegis_types::UpdateProfileRequest>,
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
    let user_id = identity.verified_user_id().map_err(HttpError::from)?;

    let request_id = context::extract_or_generate_request_id(&headers);
    let ctx = RequestContext {
        ip_address: context::extract_ip(&headers),
        user_agent: context::extract_user_agent(&headers),
        request_id: Some(request_id),
    };

    let cmd = aegis_app::UpdateProfileCommand {
        display_name: body.display_name,
    };

    let result = state.app.update_profile(user_id, cmd, &ctx).await?;

    let mapped = mapping::map_identity_result(&result);
    let meta = aegis_types::ResponseMeta::new(request_id.to_string());
    let value = serde_json::to_value(mapped).unwrap_or_default();

    Ok(Json(ApiResponse {
        data: Some(value),
        error: None,
        meta,
    }))
}
