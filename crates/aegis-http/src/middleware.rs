use aegis_app::{Cache, Clock, Hasher, IdGenerator, Repos, TokenGenerator, WebhookDispatcher};
use axum::body::Body;
use axum::http::{header::AUTHORIZATION, HeaderName, HeaderValue, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

use crate::auth::{resolve_auth_identity, AuthContext};
use crate::context;
use crate::error::HttpError;
use crate::state::AppState;

const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");
const API_TOKEN_HEADER: HeaderName = HeaderName::from_static("x-api-token");

pub async fn request_id_middleware(mut request: Request<Body>, next: Next) -> Response {
    let request_id = request
        .headers()
        .get(&REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<Uuid>().ok())
        .unwrap_or_else(Uuid::now_v7)
        .to_string();

    if let Ok(value) = HeaderValue::from_str(&request_id) {
        request.headers_mut().insert(REQUEST_ID_HEADER.clone(), value.clone());
    }

    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(REQUEST_ID_HEADER.clone(), value);
    }

    response
}

pub async fn auth_context_middleware<R, C, H, T, W, K, I>(
    state: AppState<R, C, H, T, W, K, I>,
    mut request: Request<Body>,
    next: Next,
) -> Response
where
    R: Repos,
    C: Cache,
    H: Hasher,
    T: TokenGenerator,
    W: WebhookDispatcher,
    K: Clock,
    I: IdGenerator,
{
    let identity = match context::extract_token(request.headers()) {
        Some(token) => resolve_auth_identity(&state, &token).await,
        None => None,
    };

    request.extensions_mut().insert(AuthContext(identity));
    next.run(request).await
}

pub async fn internal_auth_middleware<R, C, H, T, W, K, I>(
    state: AppState<R, C, H, T, W, K, I>,
    request: Request<Body>,
    next: Next,
) -> Response
where
    R: Repos,
    C: Cache,
    H: Hasher,
    T: TokenGenerator,
    W: WebhookDispatcher,
    K: Clock,
    I: IdGenerator,
{
    if !request.uri().path().starts_with("/v1/internal") {
        return next.run(request).await;
    }

    let expected = state.config.api.internal.api_token.as_deref();
    let Some(expected) = expected else {
        return next.run(request).await;
    };

    let token = request
        .headers()
        .get(&API_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .or_else(|| {
            request
                .headers()
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("Bearer "))
                .map(|value| value.trim().to_owned())
        });

    if token.as_deref() != Some(expected) {
        return (StatusCode::UNAUTHORIZED, HttpError(aegis_app::AppError::Unauthorized)).into_response();
    }

    next.run(request).await
}
