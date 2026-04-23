use aegis_core::{
    Actor, AuditTarget, Guest, Metadata, NewAuditEntry, PasswordCredential, SessionIdentity,
    User,
};

use crate::app::AegisApp;
use crate::dto::{AuthResult, CreateGuestCommand, GuestAuthResult, GuestConvertCommand,
    GuestEmailCommand, RequestContext};
use crate::error::AppError;
use crate::jobs::JobPayload;
use crate::ports::{AuditRepo, Cache, Clock, CredentialRepo, GuestRepo, Hasher, IdGenerator,
    OutboxRepo, PendingTokenRepo, Repos, SessionRepo, TokenGenerator, TransactionRepos, UserRepo,
    WebAuthn, WebhookDispatcher};

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
    pub async fn create_guest(
        &self,
        _cmd: CreateGuestCommand,
        ctx: &RequestContext,
    ) -> Result<GuestAuthResult, AppError> {
        let now = self.deps.clock.now();
        let guest_id = self.deps.ids.guest_id();

        let expires_at = now + self.policy().compliance.guest_ttl;

        let guest = Guest::builder(guest_id, expires_at)
            .created_at(now)
            .updated_at(now)
            .build()
            .map_err(|e| AppError::Validation(e.to_string()))?;

        let issued = self
            .issue_session(SessionIdentity::Guest(guest_id), false)
            .await?;

        let guest_clone = guest.clone();
        let session = issued.session.clone();
        let ctx = ctx.clone();

        self.deps
            .repos
            .with_transaction(|mut tx| {
                let guest = guest_clone.clone();
                let session = session.clone();
                let ctx = ctx.clone();

                async move {
                    let result = async {
                        tx.guests().insert(&guest).await?;
                        tx.sessions().insert(&session).await?;

                        let audit = NewAuditEntry {
                            event_type: "guest.create".to_owned(),
                            actor: Actor::Guest(guest_id),
                            target: Some(AuditTarget {
                                target_type: "guest".to_owned(),
                                target_id: Some(guest_id.as_uuid()),
                            }),
                            ip_address: ctx.ip_address.clone(),
                            user_agent: ctx.user_agent.clone(),
                            request_id: ctx.request_id,
                            metadata: Metadata::empty(),
                            created_at: now,
                        };
                        tx.audit().insert(&audit).await?;

                        Ok::<_, AppError>(())
                    }
                    .await;

                    (tx, result)
                }
            })
            .await?;

        Ok(GuestAuthResult {
            guest,
            session_token: issued.token,
            session_expires_at: issued.session.expires_at,
        })
    }

    pub async fn associate_guest_email(
        &self,
        guest_id: aegis_core::GuestId,
        cmd: GuestEmailCommand,
        ctx: &RequestContext,
    ) -> Result<(), AppError> {
        let email = aegis_core::EmailAddress::parse(&cmd.email)
            .map_err(|e| AppError::Validation(e.to_string()))?;

        let mut guest = self
            .deps
            .repos
            .guests()
            .get_by_id(guest_id)
            .await?
            .ok_or(AppError::NotFound("guest"))?;

        if guest.is_expired_at(self.deps.clock.now()) {
            return Err(AppError::GuestExpired);
        }

        if !guest.status.is_active() {
            return Err(AppError::GuestAlreadyConverted);
        }

        guest.associate_email_at(email, self.deps.clock.now());

        let ctx = ctx.clone();

        self.deps
            .repos
            .with_transaction(|mut tx| {
                let guest = guest.clone();
                let ctx = ctx.clone();

                async move {
                    let result = async {
                        tx.guests().update(&guest).await?;

                        let audit = NewAuditEntry {
                            event_type: "guest.associate_email".to_owned(),
                            actor: Actor::Guest(guest_id),
                            target: Some(AuditTarget {
                                target_type: "guest".to_owned(),
                                target_id: Some(guest_id.as_uuid()),
                            }),
                            ip_address: ctx.ip_address.clone(),
                            user_agent: ctx.user_agent.clone(),
                            request_id: ctx.request_id,
                            metadata: Metadata::empty(),
                            created_at: self.deps.clock.now(),
                        };
                        tx.audit().insert(&audit).await?;

                        Ok::<_, AppError>(())
                    }
                    .await;

                    (tx, result)
                }
            })
            .await
    }

    pub async fn convert_guest(
        &self,
        guest_id: aegis_core::GuestId,
        cmd: GuestConvertCommand,
        ctx: &RequestContext,
    ) -> Result<AuthResult, AppError> {
        let password = cmd.password.clone();
        let (email, display_name) = cmd.into_parts()?;

        self.policy()
            .auth
            .password_policy
            .validate(&password, email.as_ref().map(|e| e.as_str()))
            .map_err(|violations| {
                AppError::PasswordTooWeak(
                    violations
                        .iter()
                        .map(|v| v.to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                )
            })?;

        let mut guest = self
            .deps
            .repos
            .guests()
            .get_by_id(guest_id)
            .await?
            .ok_or(AppError::NotFound("guest"))?;

        if guest.is_expired_at(self.deps.clock.now()) {
            return Err(AppError::GuestExpired);
        }

        if !guest.status.can_convert() {
            return Err(AppError::GuestAlreadyConverted);
        }

        let resolved_email = match email {
            Some(e) => e,
            None => guest
                .email
                .clone()
                .ok_or_else(|| AppError::Validation("email is required for conversion".to_owned()))?,
        };

        let email_str = resolved_email.as_str().to_owned();

        if self.deps.repos.users().email_exists(&email_str).await? {
            return Err(AppError::EmailAlreadyExists);
        }

        let now = self.deps.clock.now();
        let user_id = self.deps.ids.user_id();
        let cred_id = self.deps.ids.password_cred_id();

        let user_status = if self.policy().email.enabled {
            aegis_core::UserStatus::PendingVerification
        } else {
            aegis_core::UserStatus::Active
        };

        let user = User::builder(user_id, resolved_email, display_name)
            .status(user_status)
            .metadata(guest.metadata.clone())
            .created_at(now)
            .updated_at(now)
            .build()
            .map_err(|e| AppError::Validation(e.to_string()))?;

        let hashed = self.deps.hasher.hash_password(&password).await?;
        let credential = PasswordCredential {
            id: cred_id,
            user_id,
            hash: hashed.hash,
            algorithm_version: hashed.algorithm_version as i32,
            created_at: now,
            updated_at: now,
            last_used_at: None,
        };

        guest
            .convert_to_user_at(user_id, now)
            .map_err(|_| AppError::GuestAlreadyConverted)?;

        let issued = self
            .issue_session(SessionIdentity::User(user_id), true)
            .await?;

        let pending_token_data = if self.policy().email.enabled {
            let verification_token = self
                .deps
                .tokens
                .generate_opaque(self.policy().auth.bearer_token_length)
                .await?;
            let verification_expires = now + self.policy().email.verification_token_ttl;
            let token_hash = self.deps.tokens.hash_token(&verification_token.0).await;

            let pending_token = aegis_core::PendingToken {
                token_hash,
                user_id,
                purpose: aegis_core::PendingTokenPurpose::EmailVerification,
                expires_at: verification_expires,
                created_at: now,
            };

            Some((pending_token, verification_token.0, email_str.clone()))
        } else {
            None
        };

        let user_clone = user.clone();
        let issued_session = issued.session.clone();
        let credential_clone = credential.clone();
        let guest_clone = guest.clone();
        let pending_token_data = pending_token_data.clone();
        let ctx = ctx.clone();

        let result = self
            .deps
            .repos
            .with_transaction(|mut tx| {
                let user = user_clone.clone();
                let credential = credential_clone.clone();
                let issued_session = issued_session.clone();
                let guest = guest_clone.clone();
                let pending_token_data = pending_token_data.clone();
                let ctx = ctx.clone();

                async move {
                    let result = async {
                        tx.users().insert(&user).await?;
                        tx.credentials().insert_password(&credential).await?;
                        tx.sessions().insert(&issued_session).await?;
                        tx.guests().update(&guest).await?;

                        if let Some((pending_token, raw_token, email)) = pending_token_data {
                            tx.tokens().insert(&pending_token).await?;
                            let job = JobPayload::SendVerificationEmail {
                                user_id: user_id.as_uuid(),
                                email,
                                token: raw_token,
                            };
                            tx.outbox().enqueue(&job).await?;
                        }

                        let audit = NewAuditEntry {
                            event_type: "guest.convert".to_owned(),
                            actor: Actor::Guest(guest_id),
                            target: Some(AuditTarget {
                                target_type: "user".to_owned(),
                                target_id: Some(user_id.as_uuid()),
                            }),
                            ip_address: ctx.ip_address.clone(),
                            user_agent: ctx.user_agent.clone(),
                            request_id: ctx.request_id,
                            metadata: Metadata::empty(),
                            created_at: now,
                        };
                        tx.audit().insert(&audit).await?;

                        Ok::<_, AppError>(())
                    }
                    .await;

                    (tx, result)
                }
            })
            .await;

        match result {
            Ok(()) => Ok(self.assemble_auth_result(user, issued)),
            Err(AppError::Infrastructure(msg))
                if msg.contains("duplicate key") || msg.contains("unique constraint") =>
            {
                Err(AppError::EmailAlreadyExists)
            }
            Err(e) => Err(e),
        }
    }
}
