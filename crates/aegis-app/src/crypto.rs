use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;

use crate::{AppError, AppPolicies};

const TOTP_KEY_INFO: &[u8] = b"aegis/totp/v1";
const NONCE_LEN: usize = 12;

fn master_key_material(master_key: &str) -> Vec<u8> {
    hex::decode(master_key).unwrap_or_else(|_| master_key.as_bytes().to_vec())
}

fn derive_totp_key(policies: &AppPolicies) -> Result<[u8; 32], AppError> {
    let master_key =
        policies.crypto.master_key.as_deref().ok_or_else(|| {
            AppError::Infrastructure(
                "crypto master key is required for totp".to_owned(),
            )
        })?;

    let hk = Hkdf::<Sha256>::new(None, &master_key_material(master_key));
    let mut key = [0_u8; 32];
    hk.expand(TOTP_KEY_INFO, &mut key).map_err(|_| {
        AppError::Infrastructure(
            "failed to derive totp encryption key".to_owned(),
        )
    })?;
    Ok(key)
}

pub(crate) fn encrypt_totp_secret(
    policies: &AppPolicies,
    secret: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), AppError> {
    let key = derive_totp_key(policies)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| {
        AppError::Infrastructure("failed to initialize totp cipher".to_owned())
    })?;

    let mut nonce = [0_u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), secret)
        .map_err(|_| {
            AppError::Infrastructure("failed to encrypt totp secret".to_owned())
        })?;

    Ok((ciphertext, nonce.to_vec()))
}

pub(crate) fn decrypt_totp_secret(
    policies: &AppPolicies,
    secret_encrypted: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, AppError> {
    if nonce.len() != NONCE_LEN {
        return Err(AppError::Infrastructure(
            "invalid totp nonce length".to_owned(),
        ));
    }

    let key = derive_totp_key(policies)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| {
        AppError::Infrastructure("failed to initialize totp cipher".to_owned())
    })?;

    cipher
        .decrypt(Nonce::from_slice(nonce), secret_encrypted)
        .map_err(|_| {
            AppError::Infrastructure("failed to decrypt totp secret".to_owned())
        })
}
