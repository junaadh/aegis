use aegis_app::{AegisApp, AppDeps};
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

impl<R, C, H, T, W, K, I> Clone for AppHandle<R, C, H, T, W, K, I>
where
    R: Repos + Clone,
    C: Cache + Clone,
    H: Hasher + Clone,
    T: TokenGenerator + Clone,
    W: WebhookDispatcher + Clone,
    K: Clock + Clone,
    I: IdGenerator + Clone,
{
    fn clone(&self) -> Self {
        Self {
            app: AegisApp::new(
                AppDeps {
                    repos: self.app.deps().repos.clone(),
                    cache: self.app.deps().cache.clone(),
                    hasher: self.app.deps().hasher.clone(),
                    tokens: self.app.deps().tokens.clone(),
                    webhooks: self.app.deps().webhooks.clone(),
                    clock: self.app.deps().clock.clone(),
                    ids: self.app.deps().ids.clone(),
                },
                self.app.policy().clone(),
            ),
            config: self.config.clone(),
        }
    }
}

pub type AppState<R, C, H, T, W, K, I> = Arc<AppHandle<R, C, H, T, W, K, I>>;
