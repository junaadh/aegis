use aegis_app::{AppError, TokenGenerator};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

pub struct SystemTokenGenerator;

impl SystemTokenGenerator {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SystemTokenGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl TokenGenerator for SystemTokenGenerator {
    async fn generate_opaque(&self, len: usize) -> Result<(String, [u8; 32]), AppError> {
        if len == 0 {
            return Err(AppError::Infrastructure(
                "token length must be greater than zero".to_owned(),
            ));
        }

        let mut bytes = vec![0_u8; len];
        OsRng.fill_bytes(&mut bytes);

        let token = URL_SAFE_NO_PAD.encode(&bytes);
        let hash = self.hash_token(&token).await;

        Ok((token, hash))
    }

    async fn hash_token(&self, token: &str) -> [u8; 32] {
        let digest = Sha256::digest(token.as_bytes());
        digest.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn generates_random_token_and_hash() {
        let generator = SystemTokenGenerator::new();

        let (token_a, hash_a) = generator.generate_opaque(32).await.unwrap();
        let (token_b, hash_b) = generator.generate_opaque(32).await.unwrap();

        assert!(!token_a.is_empty());
        assert_ne!(token_a, token_b);
        assert_ne!(hash_a, hash_b);
        assert_eq!(generator.hash_token(&token_a).await, hash_a);
    }

    #[tokio::test]
    async fn hashing_is_deterministic() {
        let generator = SystemTokenGenerator::new();

        let hash_a = generator.hash_token("abc").await;
        let hash_b = generator.hash_token("abc").await;
        let hash_c = generator.hash_token("xyz").await;

        assert_eq!(hash_a, hash_b);
        assert_ne!(hash_a, hash_c);
    }
}
