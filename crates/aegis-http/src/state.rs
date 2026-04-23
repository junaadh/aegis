use aegis_app::AegisApp;
use aegis_app::{Cache, Clock, Hasher, IdGenerator, Repos, TokenGenerator, WebAuthn, WebhookDispatcher};
use aegis_config::Config;
use std::sync::Arc;

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
}

pub type AppState<R, C, H, T, W, K, I, A> = Arc<AppHandle<R, C, H, T, W, K, I, A>>;
