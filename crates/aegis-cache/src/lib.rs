//! Aegis Cache — Async cache abstraction with Redis and in-memory backends.

mod error;
mod memory;

#[cfg(feature = "redis")]
mod redis_impl;

pub use error::*;
pub use memory::*;

#[cfg(feature = "redis")]
pub use redis_impl::*;

use std::future::Future;
use time::Duration;

pub trait Cache: Send + Sync {
    fn get(
        &self,
        key: &str,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, CacheError>> + Send;

    fn set(
        &self,
        key: &str,
        value: Vec<u8>,
        ttl: Duration,
    ) -> impl Future<Output = Result<(), CacheError>> + Send;

    fn delete(
        &self,
        key: &str,
    ) -> impl Future<Output = Result<(), CacheError>> + Send;

    fn ping(&self) -> impl Future<Output = Result<(), CacheError>> + Send {
        async { Ok(()) }
    }
}
