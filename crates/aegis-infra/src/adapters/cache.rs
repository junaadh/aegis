use aegis_app::{AppError, Cache as AppCache};
use aegis_cache::{Cache as BackendCache, InMemoryCache};
use aegis_config::Config;
use time::Duration;

pub struct InMemoryAppCache {
    inner: InMemoryCache,
}

impl InMemoryAppCache {
    pub fn new() -> Self {
        Self {
            inner: InMemoryCache::new(),
        }
    }
}

impl Default for InMemoryAppCache {
    fn default() -> Self {
        Self::new()
    }
}

pub struct RedisAppCache {
    inner: aegis_cache::RedisCache,
}

impl RedisAppCache {
    pub fn new(url: &str) -> Result<Self, AppError> {
        let inner = aegis_cache::RedisCache::new(url)
            .map_err(|e| AppError::Infrastructure(format!("redis cache init failed: {e}")))?;
        Ok(Self { inner })
    }
}

pub enum ConfiguredCache {
    InMemory(InMemoryAppCache),
    Redis(RedisAppCache),
}

impl ConfiguredCache {
    pub fn from_config(config: &Config) -> Result<Self, AppError> {
        if config.redis.enabled {
            Ok(Self::Redis(RedisAppCache::new(&config.redis.url)?))
        } else {
            Ok(Self::InMemory(InMemoryAppCache::new()))
        }
    }
}

fn infra_error(err: impl std::fmt::Display) -> AppError {
    AppError::Infrastructure(err.to_string())
}

#[async_trait::async_trait]
impl AppCache for InMemoryAppCache {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, AppError> {
        self.inner.get(key).await.map_err(infra_error)
    }

    async fn set(&self, key: &str, value: Vec<u8>, ttl: Duration) -> Result<(), AppError> {
        self.inner.set(key, value, ttl).await.map_err(infra_error)
    }

    async fn delete(&self, key: &str) -> Result<(), AppError> {
        self.inner.delete(key).await.map_err(infra_error)
    }
}

#[async_trait::async_trait]
impl AppCache for RedisAppCache {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, AppError> {
        self.inner.get(key).await.map_err(infra_error)
    }

    async fn set(&self, key: &str, value: Vec<u8>, ttl: Duration) -> Result<(), AppError> {
        self.inner.set(key, value, ttl).await.map_err(infra_error)
    }

    async fn delete(&self, key: &str) -> Result<(), AppError> {
        self.inner.delete(key).await.map_err(infra_error)
    }
}

#[async_trait::async_trait]
impl AppCache for ConfiguredCache {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, AppError> {
        match self {
            Self::InMemory(cache) => cache.get(key).await,
            Self::Redis(cache) => cache.get(key).await,
        }
    }

    async fn set(&self, key: &str, value: Vec<u8>, ttl: Duration) -> Result<(), AppError> {
        match self {
            Self::InMemory(cache) => cache.set(key, value, ttl).await,
            Self::Redis(cache) => cache.set(key, value, ttl).await,
        }
    }

    async fn delete(&self, key: &str) -> Result<(), AppError> {
        match self {
            Self::InMemory(cache) => cache.delete(key).await,
            Self::Redis(cache) => cache.delete(key).await,
        }
    }
}
