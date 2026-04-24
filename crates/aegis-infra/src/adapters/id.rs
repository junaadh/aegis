use aegis_app::IdGenerator;
use aegis_core::{
    GuestId, PasskeyCredentialId, PasswordCredentialId, RecoveryCodeId, RoleId,
    SessionId, TotpCredentialId, UserId, WebhookId,
};

pub struct UuidV7IdGenerator;

impl UuidV7IdGenerator {
    pub fn new() -> Self {
        Self
    }
}

impl Default for UuidV7IdGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl IdGenerator for UuidV7IdGenerator {
    fn user_id(&self) -> UserId {
        UserId::new()
    }

    fn guest_id(&self) -> GuestId {
        GuestId::new()
    }

    fn session_id(&self) -> SessionId {
        SessionId::new()
    }

    fn password_cred_id(&self) -> PasswordCredentialId {
        PasswordCredentialId::new()
    }

    fn passkey_cred_id(&self) -> PasskeyCredentialId {
        PasskeyCredentialId::new()
    }

    fn totp_cred_id(&self) -> TotpCredentialId {
        TotpCredentialId::new()
    }

    fn recovery_code_id(&self) -> RecoveryCodeId {
        RecoveryCodeId::new()
    }

    fn role_id(&self) -> RoleId {
        RoleId::new()
    }

    fn webhook_id(&self) -> WebhookId {
        WebhookId::new()
    }
}
