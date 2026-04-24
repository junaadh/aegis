use aegis_app::{AppError, EmailSender, OutboxProcessor};
use async_trait::async_trait;

#[derive(Debug, Clone, serde::Deserialize)]
struct VerificationEmailPayload {
    email: String,
    token: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct PasswordResetEmailPayload {
    email: String,
    token: String,
}

pub struct EmailOutboxProcessor<E> {
    sender: E,
}

impl<E> EmailOutboxProcessor<E> {
    pub fn new(sender: E) -> Self {
        Self { sender }
    }
}

#[async_trait]
impl<E: EmailSender> OutboxProcessor for EmailOutboxProcessor<E> {
    async fn process(
        &self,
        job_type: &str,
        payload: &str,
    ) -> Result<(), AppError> {
        match job_type {
            "send_verification_email" => {
                let p: VerificationEmailPayload = serde_json::from_str(payload)
                    .map_err(|e| {
                        AppError::Infrastructure(format!(
                            "invalid verification outbox payload: {e}"
                        ))
                    })?;
                self.sender.send_verification(&p.email, &p.token).await
            }
            "send_password_reset_email" => {
                let p: PasswordResetEmailPayload =
                    serde_json::from_str(payload).map_err(|e| {
                        AppError::Infrastructure(format!(
                            "invalid password reset outbox payload: {e}"
                        ))
                    })?;
                self.sender.send_password_reset(&p.email, &p.token).await
            }
            other => {
                tracing::warn!(job_type = other, "unsupported outbox job type");
                Ok(())
            }
        }
    }
}
