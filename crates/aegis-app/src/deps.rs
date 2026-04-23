use crate::ports::{Cache, Clock, Hasher, IdGenerator, Repos, TokenGenerator, WebAuthn, WebhookDispatcher};

pub struct AppDeps<R, C, H, T, W, K, I, A>
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
    pub repos: R,
    pub cache: C,
    pub hasher: H,
    pub tokens: T,
    pub webhooks: W,
    pub clock: K,
    pub ids: I,
    pub webauthn: A,
}
