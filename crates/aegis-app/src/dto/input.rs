use uuid::Uuid;

pub struct SignupCommand {
    pub email: String,
    pub password: String,
    pub display_name: String,
}

pub struct LoginCommand {
    pub email: String,
    pub password: String,
}

pub struct CreateGuestCommand;

pub struct GuestEmailCommand {
    pub email: String,
}

pub struct GuestConvertCommand {
    pub email: Option<String>,
    pub password: String,
    pub display_name: Option<String>,
}

pub struct UpdateProfileCommand {
    pub display_name: Option<String>,
}

pub struct ChangePasswordCommand {
    pub current_password: String,
    pub new_password: String,
}

pub struct ForgotPasswordCommand {
    pub email: String,
}

pub struct ResetPasswordCommand {
    pub token: String,
    pub new_password: String,
}

pub struct VerifyEmailCommand {
    pub token: String,
}

pub struct ResendVerificationCommand {
    pub email: String,
}

pub struct LogoutCommand {
    pub session_token_hash: [u8; 32],
}

pub struct SessionRevokeCommand {
    pub session_id: Option<Uuid>,
}

pub struct TotpEnrollFinishCommand {
    pub code: String,
}

pub struct TotpVerifyCommand {
    pub code: String,
}

pub struct ValidateSessionCommand {
    pub token_hash: [u8; 32],
}

pub struct LookupUserCommand {
    pub user_id: Uuid,
}

pub struct LookupUserByEmailCommand {
    pub email: String,
}

pub struct RegisterWebhookCommand {
    pub url: String,
    pub events: Vec<String>,
    pub secret: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct AdminUserListQuery {
    pub status: Option<String>,
    pub verified: Option<bool>,
    pub role: Option<String>,
    pub q: Option<String>,
    pub page: u32,
    pub per_page: u32,
    pub sort: Option<String>,
    pub order: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct AdminGuestListQuery {
    pub status: Option<String>,
    pub page: u32,
    pub per_page: u32,
    pub sort: Option<String>,
    pub order: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct AdminSessionListQuery {
    pub user_id: Option<Uuid>,
    pub active_only: Option<bool>,
    pub page: u32,
    pub per_page: u32,
}
