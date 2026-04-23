use std::{str::FromStr, time::Duration};

use aegis_app::{AppError, EmailSender};
use aegis_config::{Config, EmailConfig, SmtpConfig};
use lettre::{
    message::Mailbox,
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};

pub struct SmtpEmailSender {
    mailer: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

impl SmtpEmailSender {
    pub fn from_config(config: &Config) -> Result<Self, AppError> {
        Self::from_email_config(&config.email)
    }

    pub fn from_email_config(config: &EmailConfig) -> Result<Self, AppError> {
        if !config.enabled {
            return Err(AppError::Infrastructure(
                "email is disabled in config".to_owned(),
            ));
        }

        let from = if config.from_name.trim().is_empty() {
            Mailbox::from_str(&config.from_address)
        } else {
            Mailbox::from_str(&format!("{} <{}>", config.from_name, config.from_address))
        }
        .map_err(|e| AppError::Infrastructure(format!("invalid from email address: {e}")))?;

        let mailer = build_mailer(&config.smtp)?;

        Ok(Self { mailer, from })
    }

    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), AppError> {
        let to = Mailbox::from_str(to)
            .map_err(|e| AppError::Infrastructure(format!("invalid destination email address: {e}")))?;

        let message = Message::builder()
            .from(self.from.clone())
            .to(to)
            .subject(subject)
            .body(body.to_owned())
            .map_err(|e| AppError::Infrastructure(format!("failed to build email: {e}")))?;

        self.mailer
            .send(message)
            .await
            .map_err(|e| AppError::Infrastructure(format!("smtp send failed: {e}")))?;

        Ok(())
    }
}

fn build_mailer(config: &SmtpConfig) -> Result<AsyncSmtpTransport<Tokio1Executor>, AppError> {
    if config.host.trim().is_empty() {
        return Err(AppError::Infrastructure(
            "email.smtp.host is required".to_owned(),
        ));
    }

    let timeout = Some(Duration::from_secs(config.timeout_seconds));

    let builder = if config.starttls {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
            .map_err(|e| AppError::Infrastructure(format!("invalid smtp relay config: {e}")))?
            .port(config.port)
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.host).port(config.port)
    };

    let builder = if !config.username.is_empty() {
        builder.credentials(Credentials::new(
            config.username.clone(),
            config.password.clone(),
        ))
    } else {
        builder
    };

    Ok(builder.timeout(timeout).build())
}

#[async_trait::async_trait]
impl EmailSender for SmtpEmailSender {
    async fn send_verification(&self, to: &str, token: &str) -> Result<(), AppError> {
        self.send(
            to,
            "Verify your Aegis account",
            &format!("Use this verification token to verify your account: {token}"),
        )
        .await
    }

    async fn send_password_reset(&self, to: &str, token: &str) -> Result<(), AppError> {
        self.send(
            to,
            "Reset your Aegis password",
            &format!("Use this password reset token to reset your password: {token}"),
        )
        .await
    }
}
