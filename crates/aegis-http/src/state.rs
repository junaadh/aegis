use aegis_app::AegisApp;
use aegis_app::{Cache, Clock, Hasher, IdGenerator, Repos, TokenGenerator, WebhookDispatcher};
use aegis_config::Config;
use std::sync::Arc;

pub struct AppHandle<R, C, H, T, W, K, I>
where
    R: Repos,
    C: Cache,
    H: Hasher,
    T: TokenGenerator,
    W: WebhookDispatcher,
    K: Clock,
    I: IdGenerator,
{
    pub app: AegisApp<R, C, H, T, W, K, I>,
    pub config: Config,
}

pub type AppState<R, C, H, T, W, K, I> = Arc<AppHandle<R, C, H, T, W, K, I>>;
