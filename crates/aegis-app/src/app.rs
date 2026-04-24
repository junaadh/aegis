use crate::deps::AppDeps;
use crate::policy::AppPolicies;
use crate::ports::{
    Cache, Clock, Hasher, IdGenerator, Repos, TokenGenerator, WebAuthn,
    WebhookDispatcher,
};

pub struct AegisApp<R, C, H, T, W, K, I, A>
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
    pub(crate) deps: AppDeps<R, C, H, T, W, K, I, A>,
    pub(crate) policy: AppPolicies,
}

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
    pub fn new(
        deps: AppDeps<R, C, H, T, W, K, I, A>,
        policy: AppPolicies,
    ) -> Self {
        Self { deps, policy }
    }

    pub fn policy(&self) -> &AppPolicies {
        &self.policy
    }

    pub fn deps(&self) -> &AppDeps<R, C, H, T, W, K, I, A> {
        &self.deps
    }
}
