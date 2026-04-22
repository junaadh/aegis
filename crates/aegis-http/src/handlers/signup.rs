use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use aegis_app::{RequestContext, SignupCommand};
use aegis_types::{ApiResponse, SignupRequest};

use crate::auth::OptionalAuth;
use crate::context;
use crate::cookies;
use crate::error::HttpError;
use crate::mapping;
use crate::state::AppState;

pub async fn signup<R, C, H, T, W, K, I>(
    State(state): State<AppState<R, C, H, T, W, K, I>>,
    _auth: OptionalAuth,
    headers: HeaderMap,
    Json(body): Json<SignupRequest>,
) -> Result<(HeaderMap, Json<ApiResponse<serde_json::Value>>), HttpError>
where
    R: aegis_core::Repos,
    C: aegis_core::Cache,
    H: aegis_core::Hasher,
    T: aegis_core::TokenGenerator,
    W: aegis_core::WebhookDispatcher,
    K: aegis_core::Clock,
    I: aegis_core::IdGenerator,
{
    let request_id = context::extract_or_generate_request_id_from(&headers);
    let ctx = RequestContext {
        ip_address: context::extract_ip_from(&headers),
        user_agent: context::extract_user_agent_from(&headers),
        request_id: Some(request_id),
    };

    let cmd = SignupCommand {
        email: body.email,
        password: body.password,
        display_name: body.display_name,
    };

    let result = state.app.signup(cmd, &ctx).await?;

    let mut response_headers = HeaderMap::new();
    cookies::set_session_cookie(
        &mut response_headers,
        &result.session_token,
        state.app.policy().auth.session_max_age,
    );

    let auth_response = mapping::map_auth_result(&result);
    let meta = aegis_types::ResponseMeta::new(request_id.to_string());
    let value = serde_json::to_value(auth_response).unwrap_or_default();

    Ok((response_headers, Json(ApiResponse {
        data: Some(value),
        error: None,
        meta,
    })))
}
