use aegis_app::AegisApp;
use aegis_app::{
    Cache, Clock, Hasher, IdGenerator, Repos, TokenGenerator, WebAuthn,
    WebhookDispatcher,
};
use aegis_config::Config;
use aegis_infra::JwtVerifier;
use ipnet::IpNet;
use std::sync::Arc;
use std::time::Instant;

pub struct AppHandle<R, C, H, T, W, K, I, A>
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
    pub app: AegisApp<R, C, H, T, W, K, I, A>,
    pub config: Config,
    pub internal_allowed_cidrs: Arc<Vec<IpNet>>,
    pub internal_jwt_verifier: Option<Arc<JwtVerifier>>,
    pub started_at: Instant,
}

pub type AppState<R, C, H, T, W, K, I, A> =
    Arc<AppHandle<R, C, H, T, W, K, I, A>>;
