use std::sync::Arc;

use aegis_app::{
    PasskeyLoginFinishResult, PasskeyLoginStartResult, PasskeyRegisterFinishResult,
    PasskeyRegisterStartResult, WebAuthn,
};
use aegis_config::PasskeysConfig;
use async_trait::async_trait;
use base64::Engine;
use webauthn_rs::prelude::*;

pub struct WebAuthnAdapter {
    inner: Arc<Webauthn>,
}

impl WebAuthnAdapter {
    pub fn from_config(config: &PasskeysConfig) -> Result<Self, String> {
        let rp_id = &config.rp_id;
        let rp_name = &config.rp_name;

        let origin = config
            .origins
            .first()
            .ok_or("passkeys origins must not be empty")?;
        let rp_origin = Url::parse(origin)
            .map_err(|e| format!("invalid webauthn origin: {e}"))?;

        if rp_id.is_empty() {
            return Err("passkeys rp_id is required".to_owned());
        }
        if rp_name.is_empty() {
            return Err("passkeys rp_name is required".to_owned());
        }

        let builder = WebauthnBuilder::new(rp_id, &rp_origin)
            .map_err(|e| format!("failed to build webauthn: {e}"))?
            .rp_name(rp_name);

        let inner = builder
            .build()
            .map_err(|e| format!("failed to finalize webauthn builder: {e}"))?;

        Ok(Self {
            inner: Arc::new(inner),
        })
    }
}

#[async_trait]
impl WebAuthn for WebAuthnAdapter {
    async fn start_registration(
        &self,
        user_id: &str,
        user_name: &str,
        display_name: &str,
        exclude_credentials: Vec<String>,
    ) -> Result<PasskeyRegisterStartResult, aegis_app::AppError> {
        let user_uuid = Uuid::parse_str(user_id)
            .map_err(|e| aegis_app::AppError::Validation(format!("invalid user id: {e}")))?;

        let exclude: Option<Vec<CredentialID>> = if exclude_credentials.is_empty() {
            None
        } else {
            Some(
                exclude_credentials
                    .into_iter()
                    .map(|id| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&id).unwrap_or_default().into())
                    .collect(),
            )
        };

        let (ccr, state) = self
            .inner
            .start_passkey_registration(user_uuid, user_name, display_name, exclude)
            .map_err(|e| {
                aegis_app::AppError::Infrastructure(format!(
                    "failed to start passkey registration: {e}"
                ))
            })?;

        let state_bytes = serde_json::to_vec(&state).map_err(|e| {
            aegis_app::AppError::Infrastructure(format!("failed to serialize register state: {e}"))
        })?;

        let public_key = serde_json::to_value(&ccr).map_err(|e| {
            aegis_app::AppError::Infrastructure(format!(
                "failed to serialize creation challenge: {e}"
            ))
        })?;

        Ok(PasskeyRegisterStartResult {
            public_key,
            state: state_bytes,
        })
    }

    async fn finish_registration(
        &self,
        state: &[u8],
        response: &[u8],
    ) -> Result<PasskeyRegisterFinishResult, aegis_app::AppError> {
        let reg_state: PasskeyRegistration = serde_json::from_slice(state).map_err(|e| {
            aegis_app::AppError::Validation(format!("invalid registration state: {e}"))
        })?;

        let resp: RegisterPublicKeyCredential = serde_json::from_slice(response).map_err(|e| {
            aegis_app::AppError::Validation(format!("invalid registration response: {e}"))
        })?;

        let passkey = self
            .inner
            .finish_passkey_registration(&resp, &reg_state)
            .map_err(|e| {
                aegis_app::AppError::Infrastructure(format!(
                    "failed to finish passkey registration: {e}"
                ))
            })?;

        let credential_id =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(passkey.cred_id().as_slice());

        Ok(PasskeyRegisterFinishResult {
            credential_id,
            public_key: serde_json::to_vec(passkey.get_public_key()).unwrap_or_default(),
            backup_eligible: false,
            backup_state: false,
            transports: vec![],
        })
    }

    async fn start_authentication(
        &self,
        credentials: Vec<(String, Vec<u8>)>,
    ) -> Result<PasskeyLoginStartResult, aegis_app::AppError> {
        let passkeys: Vec<Passkey> = credentials
            .into_iter()
            .filter_map(|(_id, pk_bytes)| {
                if pk_bytes.is_empty() {
                    return None;
                }
                let cred: Credential = serde_json::from_slice(&pk_bytes).ok()?;
                Some(Passkey::from(cred))
            })
            .collect();

        if passkeys.is_empty() {
            return Err(aegis_app::AppError::NotFound("passkey"));
        }

        let (rcr, state) = self
            .inner
            .start_passkey_authentication(&passkeys)
            .map_err(|e| {
                aegis_app::AppError::Infrastructure(format!(
                    "failed to start passkey authentication: {e}"
                ))
            })?;

        let state_bytes = serde_json::to_vec(&state).map_err(|e| {
            aegis_app::AppError::Infrastructure(format!("failed to serialize auth state: {e}"))
        })?;

        let public_key = serde_json::to_value(&rcr).map_err(|e| {
            aegis_app::AppError::Infrastructure(format!(
                "failed to serialize auth challenge: {e}"
            ))
        })?;

        Ok(PasskeyLoginStartResult {
            public_key,
            state: state_bytes,
        })
    }

    async fn finish_authentication(
        &self,
        state: &[u8],
        response: &[u8],
    ) -> Result<PasskeyLoginFinishResult, aegis_app::AppError> {
        let auth_state: PasskeyAuthentication = serde_json::from_slice(state).map_err(|e| {
            aegis_app::AppError::Validation(format!("invalid auth state: {e}"))
        })?;

        let resp: PublicKeyCredential = serde_json::from_slice(response).map_err(|e| {
            aegis_app::AppError::Validation(format!("invalid auth response: {e}"))
        })?;

        let result = self
            .inner
            .finish_passkey_authentication(&resp, &auth_state)
            .map_err(|_| aegis_app::AppError::InvalidCredentials)?;

        let credential_id =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(result.cred_id());

        Ok(PasskeyLoginFinishResult {
            credential_id,
            sign_count: result.counter(),
        })
    }
}
