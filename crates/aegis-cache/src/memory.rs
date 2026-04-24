use std::{collections::HashMap, sync::Mutex, time::Instant};

use time::Duration;

use crate::{Cache, CacheError};

struct Entry {
    value: Vec<u8>,
    expires_at: Instant,
}

pub struct InMemoryCache {
    store: Mutex<HashMap<String, Entry>>,
}

impl InMemoryCache {
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryCache {
    fn default() -> Self {
        Self::new()
    }
}

impl Cache for InMemoryCache {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, CacheError> {
        let store = self
            .store
            .lock()
            .map_err(|e| CacheError::Backend(e.to_string()))?;
        let now = Instant::now();

        match store.get(key) {
            Some(entry) if entry.expires_at > now => {
                Ok(Some(entry.value.clone()))
            }
            _ => Ok(None),
        }
    }

    async fn set(
        &self,
        key: &str,
        value: Vec<u8>,
        ttl: Duration,
    ) -> Result<(), CacheError> {
        let mut store = self
            .store
            .lock()
            .map_err(|e| CacheError::Backend(e.to_string()))?;

        let duration_std = ttl.unsigned_abs();
        let expires_at = Instant::now() + duration_std;

        store.insert(key.to_owned(), Entry { value, expires_at });
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), CacheError> {
        let mut store = self
            .store
            .lock()
            .map_err(|e| CacheError::Backend(e.to_string()))?;
        store.remove(key);
        Ok(())
    }
}
