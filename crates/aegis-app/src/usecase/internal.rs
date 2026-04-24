use crate::app::AegisApp;
use crate::convert::core_to_output::user_to_lookup_result;
use crate::dto::{
    AdminGuestListQuery, AdminSessionListQuery, AdminUserCredentialSummary,
    AdminUserDetailResult, AdminUserListQuery, ComponentHealth, HealthResult,
    LookupUserByEmailCommand, LookupUserCommand, OverviewStats,
    PaginatedResult, RegisterWebhookCommand, SessionValidateResult,
    UserLookupResult,
};
use crate::error::AppError;
use crate::ports::{
    AuditRepo, Cache, Clock, CredentialRepo, GuestRepo, Hasher, IdGenerator,
    Repos, RoleRepo, SessionRepo, TokenGenerator, TransactionRepos, UserRepo,
    WebAuthn, WebhookDispatcher,
};
use aegis_core::{Actor, AuditTarget, Metadata, NewAuditEntry, SessionId};

impl<R, C, H, T, W, K, I, A> AegisApp<R, C, H, T, W, K, I, A>
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
    pub async fn validate_session(
        &self,
        cmd: crate::dto::ValidateSessionCommand,
    ) -> Result<SessionValidateResult, AppError> {
        let Some(session) = self
            .deps
            .repos
            .sessions()
            .get_by_token_hash(&cmd.token_hash)
            .await?
        else {
            return Ok(SessionValidateResult {
                valid: false,
                user_id: None,
                guest_id: None,
                status: None,
                expires_at: None,
                roles: None,
                mfa_verified: false,
            });
        };

        let now = self.deps.clock.now();
        if session.is_expired_at(now) {
            return Ok(SessionValidateResult {
                valid: false,
                user_id: None,
                guest_id: None,
                status: Some("expired".to_owned()),
                expires_at: Some(session.expires_at),
                roles: None,
                mfa_verified: session.mfa_verified,
            });
        }

        match session.identity {
            aegis_core::SessionIdentity::User(user_id) => {
                let user = self.deps.repos.users().get_by_id(user_id).await?;
                let Some(user) = user else {
                    return Ok(SessionValidateResult {
                        valid: false,
                        user_id: Some(user_id),
                        guest_id: None,
                        status: Some("missing_user".to_owned()),
                        expires_at: Some(session.expires_at),
                        roles: None,
                        mfa_verified: session.mfa_verified,
                    });
                };

                let roles = self
                    .deps
                    .repos
                    .roles()
                    .get_roles_by_user_id(user.id)
                    .await?;
                let role_names = roles
                    .iter()
                    .map(|role| role.name.as_str().to_owned())
                    .collect();

                let status = match user.status {
                    aegis_core::UserStatus::Active if session.mfa_verified => {
                        "active"
                    }
                    aegis_core::UserStatus::Active => "mfa_required",
                    aegis_core::UserStatus::PendingVerification
                        if session.mfa_verified =>
                    {
                        "pending_verification"
                    }
                    aegis_core::UserStatus::PendingVerification => {
                        "mfa_required"
                    }
                    aegis_core::UserStatus::Disabled => "disabled",
                    aegis_core::UserStatus::Deleted => "deleted",
                }
                .to_owned();

                Ok(SessionValidateResult {
                    valid: matches!(
                        user.status,
                        aegis_core::UserStatus::Active
                            | aegis_core::UserStatus::PendingVerification
                    ) && session.mfa_verified,
                    user_id: Some(user.id),
                    guest_id: None,
                    status: Some(status),
                    expires_at: Some(session.expires_at),
                    roles: Some(role_names),
                    mfa_verified: session.mfa_verified,
                })
            }
            aegis_core::SessionIdentity::Guest(guest_id) => {
                let guest =
                    self.deps.repos.guests().get_by_id(guest_id).await?;
                let Some(guest) = guest else {
                    return Ok(SessionValidateResult {
                        valid: false,
                        user_id: None,
                        guest_id: Some(guest_id),
                        status: Some("missing_guest".to_owned()),
                        expires_at: Some(session.expires_at),
                        roles: None,
                        mfa_verified: session.mfa_verified,
                    });
                };

                Ok(SessionValidateResult {
                    valid: !guest.is_expired_at(now)
                        && guest.status.is_active(),
                    user_id: None,
                    guest_id: Some(guest.id),
                    status: Some(format!("{:?}", guest.status).to_lowercase()),
                    expires_at: Some(session.expires_at),
                    roles: None,
                    mfa_verified: session.mfa_verified,
                })
            }
        }
    }

    pub async fn lookup_user(
        &self,
        cmd: LookupUserCommand,
    ) -> Result<UserLookupResult, AppError> {
        let user = self
            .deps
            .repos
            .users()
            .get_by_id(aegis_core::UserId::from_uuid(cmd.user_id))
            .await?
            .ok_or(AppError::NotFound("user"))?;

        let roles = self
            .deps
            .repos
            .roles()
            .get_roles_by_user_id(user.id)
            .await?;
        let role_names: Vec<String> =
            roles.iter().map(|r| r.name.as_str().to_owned()).collect();

        Ok(user_to_lookup_result(&user, Some(role_names)))
    }

    pub async fn lookup_user_by_email(
        &self,
        cmd: LookupUserByEmailCommand,
    ) -> Result<UserLookupResult, AppError> {
        let user = self
            .deps
            .repos
            .users()
            .get_by_email(&cmd.email)
            .await?
            .ok_or(AppError::NotFound("user"))?;

        let roles = self
            .deps
            .repos
            .roles()
            .get_roles_by_user_id(user.id)
            .await?;
        let role_names: Vec<String> =
            roles.iter().map(|r| r.name.as_str().to_owned()).collect();

        Ok(user_to_lookup_result(&user, Some(role_names)))
    }

    pub async fn list_admin_users(
        &self,
        query: AdminUserListQuery,
    ) -> Result<PaginatedResult<crate::dto::AdminUserListItem>, AppError> {
        self.deps.repos.users().list_admin(&query).await
    }

    pub async fn get_admin_user_detail(
        &self,
        user_id: aegis_core::UserId,
    ) -> Result<AdminUserDetailResult, AppError> {
        let user = self
            .deps
            .repos
            .users()
            .get_by_id(user_id)
            .await?
            .ok_or(AppError::NotFound("user"))?;

        let roles = self
            .deps
            .repos
            .roles()
            .get_roles_by_user_id(user_id)
            .await?
            .into_iter()
            .map(|role| role.name.as_str().to_owned())
            .collect::<Vec<_>>();
        let credentials = self
            .deps
            .repos
            .credentials()
            .list_by_user_id(user_id)
            .await?;
        let session_summary =
            self.deps.repos.sessions().get_user_summary(user_id).await?;

        let has_password = credentials
            .iter()
            .any(|cred| cred.kind == aegis_core::CredentialKind::Password);
        let passkey_count = credentials
            .iter()
            .filter(|cred| cred.kind == aegis_core::CredentialKind::Passkey)
            .count() as u64;
        let totp_enabled = credentials
            .iter()
            .any(|cred| cred.kind == aegis_core::CredentialKind::Totp);

        Ok(AdminUserDetailResult {
            id: user.id.as_uuid(),
            email: user.email.as_str().to_owned(),
            display_name: user.display_name.as_str().to_owned(),
            status: user.status.to_string(),
            email_verified_at: user.email_verified_at,
            metadata: serde_json::from_str(user.metadata.as_str())
                .unwrap_or_else(|_| serde_json::json!({})),
            roles,
            credentials: AdminUserCredentialSummary {
                has_password,
                passkey_count,
                totp_enabled,
            },
            session_count: session_summary.session_count,
            last_seen_at: session_summary.last_seen_at,
            created_at: user.created_at,
            updated_at: user.updated_at,
        })
    }

    pub async fn get_admin_user_roles(
        &self,
        user_id: aegis_core::UserId,
    ) -> Result<Vec<String>, AppError> {
        self.deps
            .repos
            .users()
            .get_by_id(user_id)
            .await?
            .ok_or(AppError::NotFound("user"))?;

        self.deps
            .repos
            .roles()
            .get_roles_by_user_id(user_id)
            .await
            .map(|roles| {
                roles
                    .into_iter()
                    .map(|role| role.name.as_str().to_owned())
                    .collect()
            })
    }

    pub async fn admin_disable_user(
        &self,
        user_id: aegis_core::UserId,
        actor_subject: &str,
        ctx: &crate::dto::RequestContext,
    ) -> Result<(), AppError> {
        self.admin_set_user_status(user_id, actor_subject, ctx, true)
            .await
    }

    pub async fn admin_enable_user(
        &self,
        user_id: aegis_core::UserId,
        actor_subject: &str,
        ctx: &crate::dto::RequestContext,
    ) -> Result<(), AppError> {
        self.admin_set_user_status(user_id, actor_subject, ctx, false)
            .await
    }

    pub async fn admin_revoke_user_sessions(
        &self,
        user_id: aegis_core::UserId,
        actor_subject: &str,
        ctx: &crate::dto::RequestContext,
    ) -> Result<(), AppError> {
        let now = self.deps.clock.now();
        let actor_subject = actor_subject.to_owned();
        let ctx = ctx.clone();
        self.deps
            .repos
            .with_transaction(|mut tx| async move {
                let result = async {
                    tx.users()
                        .get_by_id(user_id)
                        .await?
                        .ok_or(AppError::NotFound("user"))?;
                    tx.sessions().delete_by_user_id(user_id).await?;
                    tx.audit()
                        .insert(&NewAuditEntry {
                            event_type: "admin.user.revoke_sessions".to_owned(),
                            actor: Actor::Service(actor_subject),
                            target: Some(AuditTarget {
                                target_type: "user".to_owned(),
                                target_id: Some(user_id.as_uuid()),
                            }),
                            ip_address: ctx.ip_address.clone(),
                            user_agent: ctx.user_agent.clone(),
                            request_id: ctx.request_id,
                            metadata: Metadata::empty(),
                            created_at: now,
                        })
                        .await?;
                    Ok(())
                }
                .await;
                (tx, result)
            })
            .await
    }

    async fn admin_set_user_status(
        &self,
        user_id: aegis_core::UserId,
        actor_subject: &str,
        ctx: &crate::dto::RequestContext,
        disabled: bool,
    ) -> Result<(), AppError> {
        let now = self.deps.clock.now();
        let actor_subject = actor_subject.to_owned();
        let ctx = ctx.clone();

        self.deps
            .repos
            .with_transaction(|mut tx| async move {
                let result = async {
                    let mut user = tx
                        .users()
                        .get_by_id(user_id)
                        .await?
                        .ok_or(AppError::NotFound("user"))?;

                    if disabled {
                        user.disable_at(now).map_err(|err| {
                            AppError::Validation(err.to_string())
                        })?;
                    } else {
                        user.activate_at(now).map_err(|err| {
                            AppError::Validation(err.to_string())
                        })?;
                    }

                    tx.users().update(&user).await?;
                    tx.audit()
                        .insert(&NewAuditEntry {
                            event_type: if disabled {
                                "admin.user.disabled".to_owned()
                            } else {
                                "admin.user.enabled".to_owned()
                            },
                            actor: Actor::Service(actor_subject),
                            target: Some(AuditTarget {
                                target_type: "user".to_owned(),
                                target_id: Some(user_id.as_uuid()),
                            }),
                            ip_address: ctx.ip_address.clone(),
                            user_agent: ctx.user_agent.clone(),
                            request_id: ctx.request_id,
                            metadata: Metadata::empty(),
                            created_at: now,
                        })
                        .await?;
                    Ok(())
                }
                .await;
                (tx, result)
            })
            .await
    }

    pub async fn register_webhook(
        &self,
        cmd: RegisterWebhookCommand,
    ) -> Result<(), AppError> {
        let _ = cmd;
        todo!()
    }

    pub async fn health(&self) -> Result<HealthResult, AppError> {
        let db = match self.deps.repos.health_check().await {
            Ok(h) => {
                let details = serde_json::json!({
                    "poolSize": h.pool_size,
                    "poolIdle": h.pool_idle,
                });
                ComponentHealth {
                    status: "healthy".to_owned(),
                    latency_ms: Some(h.latency_ms),
                    details: Some(details),
                }
            }
            Err(e) => ComponentHealth {
                status: format!("unhealthy: {e}"),
                latency_ms: None,
                details: None,
            },
        };

        let cache = match self.deps.cache.ping().await {
            Ok(()) => ComponentHealth {
                status: "healthy".to_owned(),
                latency_ms: None,
                details: None,
            },
            Err(e) => ComponentHealth {
                status: format!("unhealthy: {e}"),
                latency_ms: None,
                details: None,
            },
        };

        let db_ok = db.status == "healthy";
        let cache_ok = cache.status == "healthy";
        let overall = if db_ok && cache_ok {
            "healthy"
        } else if db_ok {
            "degraded"
        } else {
            "unhealthy"
        };

        Ok(HealthResult {
            status: overall.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            uptime_seconds: 0,
            database: db,
            cache,
            email_enabled: false,
            outbox_pending: 0,
        })
    }

    pub async fn get_overview(&self) -> Result<OverviewStats, AppError> {
        let total_users = self.deps.repos.users().count().await?;
        let active_users =
            self.deps.repos.users().count_by_status("active").await?;
        let total_guests = self.deps.repos.guests().count().await?;
        let active_guests = self.deps.repos.guests().count_active().await?;
        let active_sessions = self.deps.repos.sessions().count_active().await?;

        Ok(OverviewStats {
            total_users,
            active_users,
            total_guests,
            active_guests,
            active_sessions,
        })
    }

    pub async fn list_admin_guests(
        &self,
        query: AdminGuestListQuery,
    ) -> Result<PaginatedResult<crate::dto::AdminGuestListItem>, AppError> {
        self.deps.repos.guests().list_admin(&query).await
    }

    pub async fn get_admin_guest_detail(
        &self,
        guest_id: aegis_core::GuestId,
    ) -> Result<crate::dto::AdminGuestDetailResult, AppError> {
        self.deps
            .repos
            .guests()
            .get_admin_detail(guest_id)
            .await?
            .ok_or(AppError::NotFound("guest"))
    }

    pub async fn list_admin_sessions(
        &self,
        query: AdminSessionListQuery,
    ) -> Result<PaginatedResult<crate::dto::AdminSessionListItem>, AppError>
    {
        self.deps.repos.sessions().list_admin(&query).await
    }

    pub async fn get_admin_session_detail(
        &self,
        session_id: SessionId,
    ) -> Result<crate::dto::AdminSessionDetailResult, AppError> {
        self.deps
            .repos
            .sessions()
            .get_admin_detail(session_id)
            .await?
            .ok_or(AppError::NotFound("session"))
    }

    pub async fn admin_revoke_session(
        &self,
        session_id: SessionId,
        actor_subject: &str,
        ctx: &crate::dto::RequestContext,
    ) -> Result<(), AppError> {
        let now = self.deps.clock.now();
        let actor_subject = actor_subject.to_owned();
        let ctx = ctx.clone();
        self.deps
            .repos
            .with_transaction(|mut tx| async move {
                let result = async {
                    tx.sessions()
                        .get_by_id(session_id)
                        .await?
                        .ok_or(AppError::NotFound("session"))?;
                    tx.sessions().delete_by_id(session_id).await?;
                    tx.audit()
                        .insert(&NewAuditEntry {
                            event_type: "admin.session.revoked".to_owned(),
                            actor: Actor::Service(actor_subject),
                            target: Some(AuditTarget {
                                target_type: "session".to_owned(),
                                target_id: Some(session_id.as_uuid()),
                            }),
                            ip_address: ctx.ip_address.clone(),
                            user_agent: ctx.user_agent.clone(),
                            request_id: ctx.request_id,
                            metadata: Metadata::empty(),
                            created_at: now,
                        })
                        .await?;
                    Ok(())
                }
                .await;
                (tx, result)
            })
            .await
    }
}
