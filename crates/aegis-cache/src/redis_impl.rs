use time::Duration;

use redis::AsyncCommands;

use crate::{Cache, CacheError};

pub struct RedisCache {
    client: redis::Client,
}

impl RedisCache {
    pub fn new(url: &str) -> Result<Self, CacheError> {
        let client = redis::Client::open(url)
            .map_err(|e| CacheError::Connection(e.to_string()))?;
        Ok(Self { client })
    }

    async fn conn(
        &self,
    ) -> Result<redis::aio::MultiplexedConnection, CacheError> {
        self.client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| CacheError::Connection(e.to_string()))
    }
}

impl Cache for RedisCache {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, CacheError> {
        let mut conn = self.conn().await?;
        conn.get(key)
            .await
            .map_err(|e| CacheError::Backend(e.to_string()))
    }

    async fn set(
        &self,
        key: &str,
        value: Vec<u8>,
        ttl: Duration,
    ) -> Result<(), CacheError> {
        let mut conn = self.conn().await?;
        let ttl_secs = ttl.whole_seconds().max(1);
        conn.set_ex(key, value, ttl_secs as u64)
            .await
            .map_err(|e| CacheError::Backend(e.to_string()))
    }

    async fn delete(&self, key: &str) -> Result<(), CacheError> {
        let mut conn = self.conn().await?;
        conn.del(key)
            .await
            .map_err(|e| CacheError::Backend(e.to_string()))
    }

    async fn ping(&self) -> Result<(), CacheError> {
        let mut conn = self.conn().await?;
        redis::cmd("PING")
            .query_async::<String>(&mut conn)
            .await
            .map_err(|e| CacheError::Connection(e.to_string()))?;
        Ok(())
    }
}
