use crate::deps::AppDeps;
use crate::policy::AppPolicies;
use crate::ports::{Cache, Clock, Hasher, IdGenerator, Repos, TokenGenerator, WebhookDispatcher};

pub struct AegisApp<R, C, H, T, W, K, I>
where
    R: Repos,
    C: Cache,
    H: Hasher,
    T: TokenGenerator,
    W: WebhookDispatcher,
    K: Clock,
    I: IdGenerator,
{
    pub(crate) deps: AppDeps<R, C, H, T, W, K, I>,
    pub(crate) policy: AppPolicies,
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
    pub fn new(deps: AppDeps<R, C, H, T, W, K, I>, policy: AppPolicies) -> Self {
        Self { deps, policy }
    }

    pub fn policy(&self) -> &AppPolicies {
        &self.policy
    }

    pub fn deps(&self) -> &AppDeps<R, C, H, T, W, K, I> {
        &self.deps
    }
}
