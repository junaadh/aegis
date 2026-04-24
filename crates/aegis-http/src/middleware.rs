use aegis_app::{
    Cache, Clock, Hasher, IdGenerator, Repos, TokenGenerator, WebAuthn,
    WebhookDispatcher,
};
use aegis_core::{ALL_VALID_PERMISSIONS, EffectivePermissions};
use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{
    HeaderName, HeaderValue, Request, StatusCode, header::AUTHORIZATION,
};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::net::{IpAddr, SocketAddr};
use uuid::Uuid;

use crate::auth::{
    AuthContext, InternalAuthContext, InternalPrincipal, resolve_auth_identity,
};
use crate::context;
use crate::error::HttpError;
use crate::state::AppState;

const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");
const API_TOKEN_HEADER: HeaderName = HeaderName::from_static("x-api-token");

pub async fn request_id_middleware(
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let request_id = request
        .headers()
        .get(&REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<Uuid>().ok())
        .unwrap_or_else(Uuid::now_v7)
        .to_string();

    if let Ok(value) = HeaderValue::from_str(&request_id) {
        request
            .headers_mut()
            .insert(REQUEST_ID_HEADER.clone(), value.clone());
    }

    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response
            .headers_mut()
            .insert(REQUEST_ID_HEADER.clone(), value);
    }

    response
}

pub async fn auth_context_middleware<R, C, H, T, W, K, I, A>(
    state: AppState<R, C, H, T, W, K, I, A>,
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
    A: WebAuthn,
{
    let identity = match context::extract_token(request.headers()) {
        Some(token) => resolve_auth_identity(&state, &token).await,
        None => None,
    };

    request.extensions_mut().insert(AuthContext(identity));
    next.run(request).await
}

pub async fn internal_network_guard<R, C, H, T, W, K, I, A>(
    state: AppState<R, C, H, T, W, K, I, A>,
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
    A: WebAuthn,
{
    if !request.uri().path().starts_with("/v1/internal") {
        return next.run(request).await;
    }

    if state.internal_allowed_cidrs.is_empty() {
        return next.run(request).await;
    }

    let request_id =
        context::extract_or_generate_request_id(request.headers()).to_string();
    let client_ip = match extract_client_ip(&request) {
        Ok(ip) => ip,
        Err(message) => {
            return HttpError::with_status(
                StatusCode::FORBIDDEN,
                aegis_types::ApiErrorCode::Forbidden,
                message,
                request_id,
            )
            .into_response();
        }
    };

    if state
        .internal_allowed_cidrs
        .iter()
        .any(|cidr| cidr.contains(&client_ip))
    {
        return next.run(request).await;
    }

    HttpError::with_status(
        StatusCode::FORBIDDEN,
        aegis_types::ApiErrorCode::Forbidden,
        "IP not allowed",
        request_id,
    )
    .into_response()
}

pub async fn internal_auth_middleware<R, C, H, T, W, K, I, A>(
    state: AppState<R, C, H, T, W, K, I, A>,
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
    A: WebAuthn,
{
    if !request.uri().path().starts_with("/v1/internal") {
        return next.run(request).await;
    }

    if let Some(verifier) = state.internal_jwt_verifier.as_ref() {
        let token = request
            .headers()
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .map(str::trim)
            .filter(|value| !value.is_empty());

        let Some(token) = token else {
            return (
                StatusCode::UNAUTHORIZED,
                HttpError::from(aegis_app::AppError::Unauthorized),
            )
                .into_response();
        };

        let principal = match verifier.verify_service_token(token) {
            Ok(principal) => InternalPrincipal::from(principal),
            Err(_) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    HttpError::from(aegis_app::AppError::Unauthorized),
                )
                    .into_response();
            }
        };

        request
            .extensions_mut()
            .insert(InternalAuthContext(Some(principal)));

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
        return (
            StatusCode::UNAUTHORIZED,
            HttpError::from(aegis_app::AppError::Unauthorized),
        )
            .into_response();
    }

    request.extensions_mut().insert(InternalAuthContext(Some(
        InternalPrincipal {
            subject: "service:legacy-static-token".to_owned(),
            permissions: EffectivePermissions::new(ALL_VALID_PERMISSIONS),
        },
    )));

    next.run(request).await
}

fn extract_client_ip(request: &Request<Body>) -> Result<IpAddr, &'static str> {
    if let Some(value) = request.headers().get("x-forwarded-for") {
        let value = value.to_str().map_err(|_| "invalid client IP")?;
        let ip = value.split(',').next().unwrap_or(value).trim();
        return ip.parse::<IpAddr>().map_err(|_| "invalid client IP");
    }

    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|connect_info| connect_info.0.ip())
        .ok_or("invalid client IP")
}
