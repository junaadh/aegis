use aegis_core::{
    Actor, AuditTarget, Metadata, NewAuditEntry, PasskeyCredential,
    SessionIdentity,
};

use crate::app::AegisApp;
use crate::dto::{AuthResult, RequestContext};
use crate::error::AppError;
use crate::ports::{
    AuditRepo, Cache, Clock, CredentialRepo, Hasher, IdGenerator, Repos,
    SessionRepo, TokenGenerator, TransactionRepos, UserRepo, WebAuthn,
    WebhookDispatcher,
};

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
    pub async fn passkey_register_start(
        &self,
        user_id: aegis_core::UserId,
    ) -> Result<serde_json::Value, AppError> {
        let user = self
            .deps
            .repos
            .users()
            .get_by_id(user_id)
            .await?
            .ok_or(AppError::NotFound("user"))?;

        let existing = self
            .deps
            .repos
            .credentials()
            .list_by_user_id(user_id)
            .await?;
        let exclude: Vec<String> = existing
            .iter()
            .filter(|c| c.kind == aegis_core::CredentialKind::Passkey)
            .map(|c| c.id.to_string())
            .collect();

        let result = self
            .deps
            .webauthn
            .start_registration(
                &user_id.to_string(),
                user.email.as_str(),
                user.display_name.as_str(),
                exclude,
            )
            .await?;

        let cache_key = format!("pk:reg:{}", user_id);
        let ttl = time::Duration::seconds(
            self.policy().passkeys.timeout_seconds as i64,
        );
        self.deps.cache.set(&cache_key, result.state, ttl).await?;

        Ok(result.public_key)
    }

    pub async fn passkey_register_finish(
        &self,
        user_id: aegis_core::UserId,
        response: Vec<u8>,
        ctx: &RequestContext,
    ) -> Result<(), AppError> {
        let cache_key = format!("pk:reg:{}", user_id);
        let state = self
            .deps
            .cache
            .get(&cache_key)
            .await?
            .ok_or(AppError::TokenInvalid)?;

        let result = self
            .deps
            .webauthn
            .finish_registration(&state, &response)
            .await?;

        let now = self.deps.clock.now();
        let cred_id = self.deps.ids.passkey_cred_id();

        let credential = PasskeyCredential {
            id: cred_id,
            user_id,
            credential_id: result.credential_id,
            public_key: result.public_key,
            attestation_object: None,
            authenticator_data: vec![],
            sign_count: 0,
            transports: result.transports,
            backup_eligible: result.backup_eligible,
            backup_state: result.backup_state,
            created_at: now,
            last_used_at: None,
        };

        let ctx = ctx.clone();
        self.deps
            .repos
            .with_transaction(|mut tx| {
                let credential = credential.clone();
                let ctx = ctx.clone();
                async move {
                    let result = async {
                        tx.credentials().insert_passkey(&credential).await?;

                        tx.audit()
                            .insert(&NewAuditEntry {
                                event_type: "user.passkey.registered"
                                    .to_owned(),
                                actor: Actor::User(user_id),
                                target: Some(AuditTarget {
                                    target_type: "credential".to_owned(),
                                    target_id: Some(credential.id.as_uuid()),
                                }),
                                ip_address: ctx.ip_address.clone(),
                                user_agent: ctx.user_agent.clone(),
                                request_id: ctx.request_id,
                                metadata: Metadata::empty(),
                                created_at: now,
                            })
                            .await?;

                        Ok::<_, AppError>(())
                    }
                    .await;
                    (tx, result)
                }
            })
            .await?;

        self.deps.cache.delete(&cache_key).await?;

        Ok(())
    }

    pub async fn passkey_login_start(
        &self,
        user_id: aegis_core::UserId,
    ) -> Result<serde_json::Value, AppError> {
        let credentials = self
            .deps
            .repos
            .credentials()
            .list_by_user_id(user_id)
            .await?;

        let mut passkey_data = Vec::new();
        for c in credentials
            .iter()
            .filter(|c| c.kind == aegis_core::CredentialKind::Passkey)
        {
            let pk = self
                .deps
                .repos
                .credentials()
                .get_passkey_by_credential_id(&c.id.to_string())
                .await?;
            if let Some(pk) = pk {
                passkey_data.push((pk.credential_id, pk.public_key));
            }
        }

        if passkey_data.is_empty() {
            return Err(AppError::NotFound("passkey"));
        }

        let result = self
            .deps
            .webauthn
            .start_authentication(passkey_data)
            .await?;

        let cache_key = format!("pk:auth:{}", user_id);
        let ttl = time::Duration::seconds(
            self.policy().passkeys.timeout_seconds as i64,
        );
        self.deps.cache.set(&cache_key, result.state, ttl).await?;

        Ok(result.public_key)
    }

    pub async fn passkey_login_finish(
        &self,
        user_id: aegis_core::UserId,
        response: Vec<u8>,
        ctx: &RequestContext,
    ) -> Result<AuthResult, AppError> {
        let cache_key = format!("pk:auth:{}", user_id);
        let state = self
            .deps
            .cache
            .get(&cache_key)
            .await?
            .ok_or(AppError::TokenInvalid)?;

        let user = self
            .deps
            .repos
            .users()
            .get_by_id(user_id)
            .await?
            .ok_or(AppError::NotFound("user"))?;

        match user.status {
            aegis_core::UserStatus::Deleted
            | aegis_core::UserStatus::Disabled => {
                return Err(AppError::Unauthorized);
            }
            aegis_core::UserStatus::PendingVerification => {
                if !self.policy().auth.allow_unverified_login {
                    return Err(AppError::EmailNotVerified);
                }
            }
            aegis_core::UserStatus::Active => {}
        }

        let auth_result = self
            .deps
            .webauthn
            .finish_authentication(&state, &response)
            .await?;

        let mut passkey = self
            .deps
            .repos
            .credentials()
            .get_passkey_by_credential_id(&auth_result.credential_id)
            .await?
            .ok_or(AppError::InvalidCredentials)?;

        let now = self.deps.clock.now();
        passkey.mark_used_at(auth_result.sign_count as i64, now);

        let issued = self
            .issue_session(SessionIdentity::User(user_id), true)
            .await?;

        let session = issued.session.clone();
        let session_id = session.id;
        let ctx = ctx.clone();
        let result = self.assemble_auth_result(user, issued);

        self.deps
            .repos
            .with_transaction(|mut tx| {
                let session = session.clone();
                let passkey = passkey.clone();
                let ctx = ctx.clone();
                async move {
                    let result = async {
                        tx.sessions().insert(&session).await?;
                        tx.credentials().update_passkey(&passkey).await?;

                        let audit = NewAuditEntry {
                            event_type: "user.login.passkey".to_owned(),
                            actor: Actor::User(user_id),
                            target: Some(AuditTarget {
                                target_type: "session".to_owned(),
                                target_id: Some(session_id.as_uuid()),
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

        self.deps.cache.delete(&cache_key).await?;

        Ok(result)
    }
}
