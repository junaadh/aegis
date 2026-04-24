use aegis_app::{
    AdminGuestListQuery as AppAdminGuestListQuery,
    AdminSessionListQuery as AppAdminSessionListQuery,
    AdminUserListQuery as AppAdminUserListQuery, LookupUserByEmailCommand,
    LookupUserCommand, ValidateSessionCommand,
};
use aegis_core::{
    AdminReadSystem, AdminReadUser, AdminUpdateUser, GuestId, SessionId,
    SessionRevokeSession, SessionValidateToken, UserId,
};
use aegis_types::{
    AdminGuestDetailResponse, AdminGuestListItemResponse, AdminGuestListQuery,
    AdminSessionDetailResponse, AdminSessionListItemResponse,
    AdminSessionListQuery, AdminUserCredentialSummaryResponse,
    AdminUserDetailResponse, AdminUserListItemResponse, AdminUserListQuery,
    ApiResponse, ComponentStatus, HealthResponse, IdentityLookupResponse,
    OverviewResponse, PaginatedResponse, SessionValidateRequest,
    UserLookupByEmailRequest, UserLookupRequest,
};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::HeaderMap;

use crate::auth::RequiredInternal;
use crate::context;
use crate::error::{ApiJson, ApiQuery, HttpError};
use crate::state::AppState;

fn format_ts(ts: time::OffsetDateTime) -> String {
    ts.format(&time::format_description::well_known::Iso8601::DEFAULT)
        .unwrap_or_default()
}

fn ok_meta(headers: &HeaderMap) -> aegis_types::ResponseMeta {
    aegis_types::ResponseMeta::new(
        context::extract_or_generate_request_id(headers).to_string(),
    )
}

pub async fn health<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    principal: RequiredInternal,
    headers: HeaderMap,
) -> Result<Json<ApiResponse<HealthResponse>>, HttpError>
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
    principal
        .principal
        .require_permission::<AdminReadSystem>()?;
    let uptime_seconds = state.started_at.elapsed().as_secs();
    let email_enabled = state.config.email.enabled;

    let result = match state.app.health().await {
        Ok(r) => r,
        Err(e) => {
            let resp = HealthResponse {
                status: "unhealthy".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                uptime_seconds,
                database: ComponentStatus {
                    status: format!("error: {e}"),
                    latency_ms: None,
                    details: None,
                },
                cache: ComponentStatus {
                    status: "unknown".to_owned(),
                    latency_ms: None,
                    details: None,
                },
                email_enabled,
                outbox_pending: 0,
            };
            return Ok(Json(ApiResponse {
                data: Some(resp),
                error: None,
                meta: aegis_types::ResponseMeta::new(request_id.to_string()),
            }));
        }
    };

    let resp = HealthResponse {
        status: result.status,
        version: result.version,
        uptime_seconds,
        database: ComponentStatus {
            status: result.database.status,
            latency_ms: result.database.latency_ms,
            details: result.database.details,
        },
        cache: ComponentStatus {
            status: result.cache.status,
            latency_ms: result.cache.latency_ms,
            details: result.cache.details,
        },
        email_enabled,
        outbox_pending: result.outbox_pending,
    };

    Ok(Json(ApiResponse {
        data: Some(resp),
        error: None,
        meta: aegis_types::ResponseMeta::new(request_id.to_string()),
    }))
}

pub async fn list_admin_users<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    principal: RequiredInternal,
    headers: HeaderMap,
    ApiQuery(query): ApiQuery<AdminUserListQuery>,
) -> Result<
    Json<ApiResponse<PaginatedResponse<AdminUserListItemResponse>>>,
    HttpError,
>
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
    principal.principal.require_permission::<AdminReadUser>()?;
    let result = state
        .app
        .list_admin_users(AppAdminUserListQuery {
            status: query.status,
            verified: query.verified,
            role: query.role,
            q: query.q,
            page: query.page.unwrap_or(1),
            per_page: query.per_page.unwrap_or(50),
            sort: query.sort,
            order: query.order,
        })
        .await?;

    Ok(Json(ApiResponse {
        data: Some(PaginatedResponse {
            items: result
                .items
                .into_iter()
                .map(|item| AdminUserListItemResponse {
                    id: item.id.to_string(),
                    email: item.email,
                    display_name: item.display_name,
                    status: item.status,
                    email_verified: item.email_verified,
                    created_at: format_ts(item.created_at),
                    updated_at: format_ts(item.updated_at),
                })
                .collect(),
            page: result.page,
            per_page: result.per_page,
            total: result.total,
        }),
        error: None,
        meta: ok_meta(&headers),
    }))
}

pub async fn admin_user_detail<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    principal: RequiredInternal,
    headers: HeaderMap,
    Path(user_id): Path<uuid::Uuid>,
) -> Result<Json<ApiResponse<AdminUserDetailResponse>>, HttpError>
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
    principal.principal.require_permission::<AdminReadUser>()?;
    let result = state
        .app
        .get_admin_user_detail(UserId::from_uuid(user_id))
        .await?;

    Ok(Json(ApiResponse {
        data: Some(AdminUserDetailResponse {
            id: result.id.to_string(),
            email: result.email,
            display_name: result.display_name,
            status: result.status,
            email_verified_at: result.email_verified_at.map(format_ts),
            metadata: result.metadata,
            roles: result.roles,
            credentials: AdminUserCredentialSummaryResponse {
                has_password: result.credentials.has_password,
                passkey_count: result.credentials.passkey_count,
                totp_enabled: result.credentials.totp_enabled,
            },
            session_count: result.session_count,
            last_seen_at: result.last_seen_at.map(format_ts),
            created_at: format_ts(result.created_at),
            updated_at: format_ts(result.updated_at),
        }),
        error: None,
        meta: ok_meta(&headers),
    }))
}

pub async fn admin_user_roles<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    principal: RequiredInternal,
    headers: HeaderMap,
    Path(user_id): Path<uuid::Uuid>,
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
    principal.principal.require_permission::<AdminReadUser>()?;
    let roles = state
        .app
        .get_admin_user_roles(UserId::from_uuid(user_id))
        .await?;
    Ok(Json(ApiResponse {
        data: Some(serde_json::json!({ "roles": roles })),
        error: None,
        meta: ok_meta(&headers),
    }))
}

pub async fn admin_disable_user<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    principal: RequiredInternal,
    headers: HeaderMap,
    Path(user_id): Path<uuid::Uuid>,
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
    principal
        .principal
        .require_permission::<AdminUpdateUser>()?;
    let ctx = aegis_app::RequestContext {
        ip_address: context::extract_ip(&headers),
        user_agent: context::extract_user_agent(&headers),
        request_id: Some(context::extract_or_generate_request_id(&headers)),
    };
    state
        .app
        .admin_disable_user(
            UserId::from_uuid(user_id),
            &principal.principal.subject,
            &ctx,
        )
        .await?;
    Ok(Json(ApiResponse {
        data: Some(serde_json::json!({ "status": "disabled" })),
        error: None,
        meta: ok_meta(&headers),
    }))
}

pub async fn admin_enable_user<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    principal: RequiredInternal,
    headers: HeaderMap,
    Path(user_id): Path<uuid::Uuid>,
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
    principal
        .principal
        .require_permission::<AdminUpdateUser>()?;
    let ctx = aegis_app::RequestContext {
        ip_address: context::extract_ip(&headers),
        user_agent: context::extract_user_agent(&headers),
        request_id: Some(context::extract_or_generate_request_id(&headers)),
    };
    state
        .app
        .admin_enable_user(
            UserId::from_uuid(user_id),
            &principal.principal.subject,
            &ctx,
        )
        .await?;
    Ok(Json(ApiResponse {
        data: Some(serde_json::json!({ "status": "active" })),
        error: None,
        meta: ok_meta(&headers),
    }))
}

pub async fn admin_revoke_user_sessions<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    principal: RequiredInternal,
    headers: HeaderMap,
    Path(user_id): Path<uuid::Uuid>,
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
    principal
        .principal
        .require_permission::<AdminUpdateUser>()?;
    let ctx = aegis_app::RequestContext {
        ip_address: context::extract_ip(&headers),
        user_agent: context::extract_user_agent(&headers),
        request_id: Some(context::extract_or_generate_request_id(&headers)),
    };
    state
        .app
        .admin_revoke_user_sessions(
            UserId::from_uuid(user_id),
            &principal.principal.subject,
            &ctx,
        )
        .await?;
    Ok(Json(ApiResponse {
        data: Some(serde_json::json!({ "status": "sessions_revoked" })),
        error: None,
        meta: ok_meta(&headers),
    }))
}

pub async fn validate_session<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    principal: RequiredInternal,
    headers: HeaderMap,
    ApiJson(body): ApiJson<SessionValidateRequest>,
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
    principal
        .principal
        .require_permission::<SessionValidateToken>()?;
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
        meta: aegis_types::ResponseMeta::new(request_id.to_string()),
    }))
}

pub async fn lookup_user<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    principal: RequiredInternal,
    headers: HeaderMap,
    ApiJson(body): ApiJson<UserLookupRequest>,
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
    principal.principal.require_permission::<AdminReadUser>()?;
    let result = state
        .app
        .lookup_user(LookupUserCommand {
            user_id: body.user_id,
        })
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
        meta: aegis_types::ResponseMeta::new(request_id.to_string()),
    }))
}

pub async fn lookup_user_by_email<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    principal: RequiredInternal,
    headers: HeaderMap,
    ApiJson(body): ApiJson<UserLookupByEmailRequest>,
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
    principal.principal.require_permission::<AdminReadUser>()?;
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
        meta: aegis_types::ResponseMeta::new(request_id.to_string()),
    }))
}

pub async fn lookup_user_by_email_query<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    principal: RequiredInternal,
    headers: HeaderMap,
    ApiQuery(query): ApiQuery<UserLookupByEmailRequest>,
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
    principal.principal.require_permission::<AdminReadUser>()?;
    let result = state
        .app
        .lookup_user_by_email(LookupUserByEmailCommand { email: query.email })
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
        meta: ok_meta(&headers),
    }))
}

pub async fn overview<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    principal: RequiredInternal,
    headers: HeaderMap,
) -> Result<Json<ApiResponse<OverviewResponse>>, HttpError>
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
    principal
        .principal
        .require_permission::<AdminReadSystem>()?;
    let stats = state.app.get_overview().await?;

    Ok(Json(ApiResponse {
        data: Some(OverviewResponse {
            total_users: stats.total_users,
            active_users: stats.active_users,
            total_guests: stats.total_guests,
            active_guests: stats.active_guests,
            active_sessions: stats.active_sessions,
            email_enabled: state.config.email.enabled,
        }),
        error: None,
        meta: ok_meta(&headers),
    }))
}

pub async fn list_admin_guests<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    principal: RequiredInternal,
    headers: HeaderMap,
    ApiQuery(query): ApiQuery<AdminGuestListQuery>,
) -> Result<
    Json<ApiResponse<PaginatedResponse<AdminGuestListItemResponse>>>,
    HttpError,
>
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
    principal.principal.require_permission::<AdminReadUser>()?;
    let result = state
        .app
        .list_admin_guests(AppAdminGuestListQuery {
            status: query.status,
            page: query.page.unwrap_or(1),
            per_page: query.per_page.unwrap_or(50),
            sort: query.sort,
            order: query.order,
        })
        .await?;

    Ok(Json(ApiResponse {
        data: Some(PaginatedResponse {
            items: result
                .items
                .into_iter()
                .map(|item| AdminGuestListItemResponse {
                    id: item.id.to_string(),
                    email: item.email,
                    status: item.status,
                    converted_to: item.converted_to.map(|id| id.to_string()),
                    expires_at: format_ts(item.expires_at),
                    created_at: format_ts(item.created_at),
                    updated_at: format_ts(item.updated_at),
                })
                .collect(),
            page: result.page,
            per_page: result.per_page,
            total: result.total,
        }),
        error: None,
        meta: ok_meta(&headers),
    }))
}

pub async fn admin_guest_detail<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    principal: RequiredInternal,
    headers: HeaderMap,
    Path(guest_id): Path<uuid::Uuid>,
) -> Result<Json<ApiResponse<AdminGuestDetailResponse>>, HttpError>
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
    principal.principal.require_permission::<AdminReadUser>()?;
    let result = state
        .app
        .get_admin_guest_detail(GuestId::from_uuid(guest_id))
        .await?;

    Ok(Json(ApiResponse {
        data: Some(AdminGuestDetailResponse {
            id: result.id.to_string(),
            email: result.email,
            status: result.status,
            converted_to: result.converted_to.map(|id| id.to_string()),
            metadata: result.metadata,
            expires_at: format_ts(result.expires_at),
            created_at: format_ts(result.created_at),
            updated_at: format_ts(result.updated_at),
        }),
        error: None,
        meta: ok_meta(&headers),
    }))
}

pub async fn list_admin_sessions<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    principal: RequiredInternal,
    headers: HeaderMap,
    ApiQuery(query): ApiQuery<AdminSessionListQuery>,
) -> Result<
    Json<ApiResponse<PaginatedResponse<AdminSessionListItemResponse>>>,
    HttpError,
>
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
    principal
        .principal
        .require_permission::<aegis_core::SessionReadSession>()?;
    let result = state
        .app
        .list_admin_sessions(AppAdminSessionListQuery {
            user_id: query.user_id,
            active_only: query.active_only,
            page: query.page.unwrap_or(1),
            per_page: query.per_page.unwrap_or(50),
        })
        .await?;

    Ok(Json(ApiResponse {
        data: Some(PaginatedResponse {
            items: result
                .items
                .into_iter()
                .map(|item| AdminSessionListItemResponse {
                    id: item.id.to_string(),
                    identity_type: item.identity_type,
                    identity_id: item.identity_id.to_string(),
                    expires_at: format_ts(item.expires_at),
                    last_seen_at: format_ts(item.last_seen_at),
                    mfa_verified: item.mfa_verified,
                    user_agent: item.user_agent,
                    ip_address: item.ip_address,
                })
                .collect(),
            page: result.page,
            per_page: result.per_page,
            total: result.total,
        }),
        error: None,
        meta: ok_meta(&headers),
    }))
}

pub async fn admin_session_detail<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    principal: RequiredInternal,
    headers: HeaderMap,
    Path(session_id): Path<uuid::Uuid>,
) -> Result<Json<ApiResponse<AdminSessionDetailResponse>>, HttpError>
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
    principal
        .principal
        .require_permission::<aegis_core::SessionReadSession>()?;
    let result = state
        .app
        .get_admin_session_detail(SessionId::from_uuid(session_id))
        .await?;

    Ok(Json(ApiResponse {
        data: Some(AdminSessionDetailResponse {
            id: result.id.to_string(),
            identity_type: result.identity_type,
            identity_id: result.identity_id.to_string(),
            expires_at: format_ts(result.expires_at),
            last_seen_at: format_ts(result.last_seen_at),
            mfa_verified: result.mfa_verified,
            user_agent: result.user_agent,
            ip_address: result.ip_address,
            metadata: result.metadata,
        }),
        error: None,
        meta: ok_meta(&headers),
    }))
}

pub async fn admin_revoke_session<R, C, H, T, W, K, I, A>(
    State(state): State<AppState<R, C, H, T, W, K, I, A>>,
    principal: RequiredInternal,
    headers: HeaderMap,
    Path(session_id): Path<uuid::Uuid>,
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
    principal
        .principal
        .require_permission::<SessionRevokeSession>()?;
    let ctx = aegis_app::RequestContext {
        ip_address: context::extract_ip(&headers),
        user_agent: context::extract_user_agent(&headers),
        request_id: Some(context::extract_or_generate_request_id(&headers)),
    };
    state
        .app
        .admin_revoke_session(
            SessionId::from_uuid(session_id),
            &principal.principal.subject,
            &ctx,
        )
        .await?;
    Ok(Json(ApiResponse {
        data: Some(serde_json::json!({ "status": "revoked" })),
        error: None,
        meta: ok_meta(&headers),
    }))
}
