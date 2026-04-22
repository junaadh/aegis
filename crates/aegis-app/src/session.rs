use aegis_core::{Session, SessionIdentity};

use crate::app::AegisApp;
use crate::dto::{AuthResult, LoginOutcome};
use crate::error::AppError;
use crate::ports::{Clock, IdGenerator, Repos, TokenGenerator, WebhookDispatcher, Cache, Hasher};

pub struct IssuedSession {
    pub token: String,
    pub session: Session,
}

impl<R, C, H, T, W, K, I> AegisApp<R, C, H, T, W, K, I>
where
    R: Repos,
    C: Cache,
    H: Hasher,
    T: TokenGenerator,
    W: WebhookDispatcher,
    K: Clock,
    I: IdGenerator,
{
    pub(crate) async fn issue_session(
        &self,
        identity: SessionIdentity,
        mfa_verified: bool,
    ) -> Result<IssuedSession, AppError> {
        let now = self.deps.clock.now();
        let session_id = self.deps.ids.session_id();

        let (token, token_hash) = self
            .deps
            .tokens
            .generate_opaque(self.policy().auth.bearer_token_length)
            .await?;

        let expires_at = now + self.policy().auth.session_max_age;

        let session = Session::builder(session_id, token_hash, identity, expires_at)
            .mfa_verified(mfa_verified)
            .build();

        Ok(IssuedSession { token, session })
    }

    pub(crate) fn assemble_auth_result(
        &self,
        user: aegis_core::User,
        issued: IssuedSession,
    ) -> AuthResult {
        AuthResult {
            user,
            session_token: issued.token,
            session_expires_at: issued.session.expires_at,
            mfa_verified: issued.session.mfa_verified,
        }
    }

    pub(crate) fn assemble_login_outcome(
        &self,
        user: aegis_core::User,
        issued: IssuedSession,
    ) -> LoginOutcome {
        if issued.session.mfa_verified {
            LoginOutcome::Authenticated(self.assemble_auth_result(user, issued))
        } else {
            LoginOutcome::RequiresMfa {
                session_token: issued.token,
                session_expires_at: issued.session.expires_at,
            }
        }
    }
}
