use std::fmt;

use uuid::Uuid;

#[derive(Debug, Clone)]
pub enum JobPayload {
    SendVerificationEmail {
        user_id: Uuid,
        email: String,
        token: String,
    },
    SendPasswordResetEmail {
        user_id: Uuid,
        email: String,
        token: String,
    },
    SendMfaEnrolledNotification {
        user_id: Uuid,
    },
    CleanupExpiredSessions,
    CleanupExpiredGuests,
}

impl fmt::Display for JobPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.job_type())
    }
}

impl JobPayload {
    pub fn job_type(&self) -> &'static str {
        match self {
            Self::SendVerificationEmail { .. } => "send_verification_email",
            Self::SendPasswordResetEmail { .. } => "send_password_reset_email",
            Self::SendMfaEnrolledNotification { .. } => {
                "send_mfa_enrolled_notification"
            }
            Self::CleanupExpiredSessions => "cleanup_expired_sessions",
            Self::CleanupExpiredGuests => "cleanup_expired_guests",
        }
    }
}
