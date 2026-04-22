use aegis_app::{
    AppError, Cache, Clock, GuestRepo, Hasher, IdGenerator, Repos, SessionRepo, TokenGenerator,
    UserRepo, WebhookDispatcher,
};
use aegis_core::{Identity, SessionIdentity};
use axum::http::HeaderMap;

use crate::context;
use crate::state::AppState;

#[derive(Debug, Clone)]
pub struct AuthIdentity {
    pub inner: Identity,
    pub session_token_hash: [u8; 32],
}

pub async fn extract_required_auth<R, C, H, T, W, K, I>(
    state: &AppState<R, C, H, T, W, K, I>,
    headers: &HeaderMap,
) -> Result<AuthIdentity, AppError>
where
    R: Repos,
    C: Cache,
    H: Hasher,
    T: TokenGenerator,
    W: WebhookDispatcher,
    K: Clock,
    I: IdGenerator,
{
    let token = context::extract_token(headers).ok_or(AppError::Unauthorized)?;
    resolve_auth_inner(state, &token)
        .await
        .ok_or(AppError::Unauthorized)
}

pub async fn extract_optional_auth<R, C, H, T, W, K, I>(
    state: &AppState<R, C, H, T, W, K, I>,
    headers: &HeaderMap,
) -> Option<AuthIdentity>
where
    R: Repos,
    C: Cache,
    H: Hasher,
    T: TokenGenerator,
    W: WebhookDispatcher,
    K: Clock,
    I: IdGenerator,
{
    let token = context::extract_token(headers)?;
    resolve_auth_inner(state, &token).await
}

async fn resolve_auth_inner<R, C, H, T, W, K, I>(
    state: &AppState<R, C, H, T, W, K, I>,
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
                aegis_core::UserStatus::Active
                | aegis_core::UserStatus::PendingVerification => {
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
    })
}

impl AuthIdentity {
    pub fn user_id(&self) -> Result<aegis_core::UserId, AppError> {
        match &self.inner {
            Identity::User(u) => Ok(u.id),
            Identity::Guest(_) => Err(AppError::Forbidden),
        }
    }

    pub fn guest_id(&self) -> Result<aegis_core::GuestId, AppError> {
        match &self.inner {
            Identity::Guest(g) => Ok(g.id),
            Identity::User(_) => Err(AppError::Forbidden),
        }
    }
}
