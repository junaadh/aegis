use crate::ports::{Cache, Clock, Hasher, IdGenerator, Repos, TokenGenerator, WebhookDispatcher};

pub struct AppDeps<R, C, H, T, W, K, I>
where
    R: Repos,
    C: Cache,
    H: Hasher,
    T: TokenGenerator,
    W: WebhookDispatcher,
    K: Clock,
    I: IdGenerator,
{
    pub repos: R,
    pub cache: C,
    pub hasher: H,
    pub tokens: T,
    pub webhooks: W,
    pub clock: K,
    pub ids: I,
}
