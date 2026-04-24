use aegis_core::{
    GuestId, PasskeyCredentialId, PasswordCredentialId, RecoveryCodeId, RoleId,
    SessionId, TotpCredentialId, UserId, WebhookId,
};

pub trait IdGenerator: Send + Sync {
    fn user_id(&self) -> UserId;
    fn guest_id(&self) -> GuestId;
    fn session_id(&self) -> SessionId;
    fn password_cred_id(&self) -> PasswordCredentialId;
    fn passkey_cred_id(&self) -> PasskeyCredentialId;
    fn totp_cred_id(&self) -> TotpCredentialId;
    fn recovery_code_id(&self) -> RecoveryCodeId;
    fn role_id(&self) -> RoleId;
    fn webhook_id(&self) -> WebhookId;
}
