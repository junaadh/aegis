use std::marker::PhantomData;

use aegis_app::{
    Cache, Clock, GuestRepo, Hasher, IdGenerator, Repos, SessionRepo,
    TokenGenerator, UserRepo, WebAuthn, WebhookDispatcher,
};
use aegis_core::{
    EffectivePermissions, Identity, NamedPermission, ServicePrincipal,
    SessionIdentity, UserStatus,
};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::error::HttpError;
use crate::state::AppState;

#[derive(Debug, Clone)]
pub struct AuthIdentity {
    pub inner: Identity,
    pub session_token_hash: [u8; 32],
    pub mfa_verified: bool,
}

#[derive(Debug, Clone, Default)]
pub struct AuthContext(pub Option<AuthIdentity>);

#[derive(Debug, Clone, Default)]
pub struct InternalAuthContext(pub Option<InternalPrincipal>);

#[derive(Debug, Clone)]
pub struct InternalPrincipal {
    #[allow(dead_code)]
    pub subject: String,
    pub permissions: EffectivePermissions,
}

pub struct OptionalAuth<R, C, H, T, W, K, I, A> {
    pub identity: Option<AuthIdentity>,
    _marker: PhantomData<(R, C, H, T, W, K, I, A)>,
}

pub struct RequiredAuth<R, C, H, T, W, K, I, A> {
    pub identity: AuthIdentity,
    _marker: PhantomData<(R, C, H, T, W, K, I, A)>,
}

pub struct RequiredInternal {
    pub principal: InternalPrincipal,
}

impl<R, C, H, T, W, K, I, A> OptionalAuth<R, C, H, T, W, K, I, A> {
    fn new(identity: Option<AuthIdentity>) -> Self {
        Self {
            identity,
            _marker: PhantomData,
        }
    }
}

impl<R, C, H, T, W, K, I, A> RequiredAuth<R, C, H, T, W, K, I, A> {
    fn new(identity: AuthIdentity) -> Self {
        Self {
            identity,
            _marker: PhantomData,
        }
    }
}

impl From<ServicePrincipal> for InternalPrincipal {
    fn from(value: ServicePrincipal) -> Self {
        Self {
            subject: value.subject,
            permissions: value.permissions,
        }
    }
}

impl InternalPrincipal {
    pub fn require_permission<P: NamedPermission>(
        &self,
    ) -> Result<(), aegis_app::AppError> {
        self.permissions
            .require_named::<P>()
            .map_err(|_| aegis_app::AppError::Forbidden)
    }
}

impl<S, R, C, H, T, W, K, I, A> FromRequestParts<S>
    for OptionalAuth<R, C, H, T, W, K, I, A>
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send
    {
        let identity = parts
            .extensions
            .get::<AuthContext>()
            .and_then(|ctx| ctx.0.clone());

        async move { Ok(Self::new(identity)) }
    }
}

impl<S, R, C, H, T, W, K, I, A> FromRequestParts<S>
    for RequiredAuth<R, C, H, T, W, K, I, A>
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send
    {
        let identity = parts
            .extensions
            .get::<AuthContext>()
            .and_then(|ctx| ctx.0.clone());

        async move {
            let identity = identity.ok_or_else(|| {
                HttpError::from(aegis_app::AppError::Unauthorized)
            })?;
            Ok(Self::new(identity))
        }
    }
}

impl<S> FromRequestParts<S> for RequiredInternal
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send
    {
        let principal = parts
            .extensions
            .get::<InternalAuthContext>()
            .and_then(|ctx| ctx.0.clone());

        async move {
            let principal = principal.ok_or_else(|| {
                HttpError::from(aegis_app::AppError::Unauthorized)
            })?;
            Ok(Self { principal })
        }
    }
}

pub async fn resolve_auth_identity<R, C, H, T, W, K, I, A>(
    state: &AppState<R, C, H, T, W, K, I, A>,
    token: &str,
) -> Option<AuthIdentity>
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
    let deps = state.app.deps();
    let hash = deps.tokens.hash_token(token).await;
    let session = deps
        .repos
        .sessions()
        .get_by_token_hash(&hash)
        .await
        .ok()??;

    let now = deps.clock.now();
    if session.is_expired_at(now) {
        return None;
    }

    let identity = match session.identity {
        SessionIdentity::User(id) => {
            let user = deps.repos.users().get_by_id(id).await.ok()??;
            match user.status {
                UserStatus::Active | UserStatus::PendingVerification => {
                    Identity::User(aegis_core::UserIdentity {
                        id: user.id,
                        status: user.status,
                        email_verified: user.is_email_verified(),
                        metadata: user.metadata.clone(),
                    })
                }
                _ => return None,
            }
        }
        SessionIdentity::Guest(id) => {
            let guest = deps.repos.guests().get_by_id(id).await.ok()??;
            if guest.is_expired_at(now) || !guest.status.is_active() {
                return None;
            }
            Identity::Guest(aegis_core::GuestIdentity {
                id: guest.id,
                status: guest.status,
                metadata: guest.metadata.clone(),
            })
        }
    };

    Some(AuthIdentity {
        inner: identity,
        session_token_hash: hash,
        mfa_verified: session.mfa_verified,
    })
}

impl AuthIdentity {
    pub fn user_id(&self) -> Result<aegis_core::UserId, aegis_app::AppError> {
        match &self.inner {
            Identity::User(user) => Ok(user.id),
            Identity::Guest(_) => Err(aegis_app::AppError::Forbidden),
        }
    }

    pub fn guest_id(&self) -> Result<aegis_core::GuestId, aegis_app::AppError> {
        match &self.inner {
            Identity::Guest(guest) => Ok(guest.id),
            Identity::User(_) => Err(aegis_app::AppError::Forbidden),
        }
    }

    pub fn verified_user_id(
        &self,
    ) -> Result<aegis_core::UserId, aegis_app::AppError> {
        let user_id = self.user_id()?;
        if self.mfa_verified {
            Ok(user_id)
        } else {
            Err(aegis_app::AppError::MfaRequired)
        }
    }
}
