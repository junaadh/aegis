use aegis_app::{AppError, Hasher, PasswordHash, PasswordVerifyResult};
use aegis_config::{Argon2Config, Config, HashingAlgorithm, PasswordConfig};
use argon2::{
    password_hash::{PasswordHash as ParsedPasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use rand::rngs::OsRng;

const ARGON2_VERSION: u32 = 1;

pub struct Argon2Hasher {
    inner: Argon2<'static>,
    version: u32,
}

impl Argon2Hasher {
    pub fn from_config(config: &Config) -> Result<Self, AppError> {
        Self::from_password_config(&config.credentials.password)
    }

    pub fn from_password_config(config: &PasswordConfig) -> Result<Self, AppError> {
        match config.hashing_algorithm {
            HashingAlgorithm::Argon2id => Self::from_argon2_config(&config.argon2),
        }
    }

    pub fn from_argon2_config(config: &Argon2Config) -> Result<Self, AppError> {
        let params = Params::new(config.memory_cost, config.time_cost, config.parallelism, None)
            .map_err(|e| AppError::Infrastructure(format!("invalid argon2 config: {e}")))?;

        Ok(Self {
            inner: Argon2::new(Algorithm::Argon2id, Version::V0x13, params),
            version: ARGON2_VERSION,
        })
    }
}

#[async_trait::async_trait]
impl Hasher for Argon2Hasher {
    fn current_algorithm_version(&self) -> u32 {
        self.version
    }

    async fn hash_password(&self, password: &str) -> Result<PasswordHash, AppError> {
        let salt = SaltString::generate(&mut OsRng);
        let hash = self
            .inner
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AppError::Infrastructure(format!("argon2 hash failed: {e}")))?
            .to_string();

        Ok(PasswordHash {
            hash,
            algorithm_version: self.version,
        })
    }

    async fn verify_password(
        &self,
        password: &str,
        hash: &str,
        stored_version: u32,
    ) -> Result<PasswordVerifyResult, AppError> {
        let parsed = ParsedPasswordHash::new(hash)
            .map_err(|e| AppError::Infrastructure(format!("invalid stored password hash: {e}")))?;

        match self.inner.verify_password(password.as_bytes(), &parsed) {
            Ok(()) => {
                if stored_version < self.version {
                    Ok(PasswordVerifyResult::ValidButRehashNeeded {
                        current_version: self.version,
                    })
                } else {
                    Ok(PasswordVerifyResult::Valid)
                }
            }
            Err(argon2::password_hash::Error::Password) => Ok(PasswordVerifyResult::Invalid),
            Err(e) => Err(AppError::Infrastructure(format!("argon2 verify failed: {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hashes_and_verifies_password() {
        let hasher = Argon2Hasher::from_argon2_config(&Argon2Config {
            time_cost: 2,
            memory_cost: 19_456,
            parallelism: 1,
        })
        .unwrap();

        let hash = hasher.hash_password("CorrectHorseBatteryStaple1!").await.unwrap();

        match hasher
            .verify_password(
                "CorrectHorseBatteryStaple1!",
                &hash.hash,
                hash.algorithm_version,
            )
            .await
            .unwrap()
        {
            PasswordVerifyResult::Valid => {}
            _ => panic!("unexpected verify result"),
        }

        match hasher.verify_password("wrong", &hash.hash, hash.algorithm_version).await.unwrap() {
            PasswordVerifyResult::Invalid => {}
            _ => panic!("unexpected verify result"),
        }
    }

    #[tokio::test]
    async fn reports_rehash_needed_for_old_version() {
        let hasher = Argon2Hasher::from_argon2_config(&Argon2Config {
            time_cost: 2,
            memory_cost: 19_456,
            parallelism: 1,
        })
        .unwrap();

        let hash = hasher.hash_password("Password1!").await.unwrap();

        match hasher.verify_password("Password1!", &hash.hash, 0).await.unwrap() {
            PasswordVerifyResult::ValidButRehashNeeded { current_version } => {
                assert_eq!(current_version, 1)
            }
            _ => panic!("unexpected verify result"),
        }
    }
}
