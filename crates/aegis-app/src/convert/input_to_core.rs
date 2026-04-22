use aegis_core::{DisplayName, EmailAddress};

use crate::dto::{GuestConvertCommand, LoginCommand, SignupCommand, UpdateProfileCommand};
use crate::error::AppError;

impl SignupCommand {
    pub fn into_parts(self) -> Result<(EmailAddress, DisplayName), AppError> {
        let email = EmailAddress::parse(&self.email)
            .map_err(|e| AppError::Validation(e.to_string()))?;
        let display_name = DisplayName::parse(&self.display_name)
            .map_err(|e| AppError::Validation(e.to_string()))?;
        Ok((email, display_name))
    }
}

impl LoginCommand {
    pub fn parse_email(&self) -> Result<EmailAddress, AppError> {
        EmailAddress::parse(&self.email).map_err(|e| AppError::Validation(e.to_string()))
    }
}

impl UpdateProfileCommand {
    pub fn parse_display_name(&self) -> Result<Option<DisplayName>, AppError> {
        self.display_name
            .as_deref()
            .map(DisplayName::parse)
            .transpose()
            .map_err(|e| AppError::Validation(e.to_string()))
    }
}

impl GuestConvertCommand {
    pub fn into_parts(self) -> Result<(Option<EmailAddress>, DisplayName), AppError> {
        let email = self
            .email
            .as_deref()
            .map(EmailAddress::parse)
            .transpose()
            .map_err(|e| AppError::Validation(e.to_string()))?;

        let display_name = match self.display_name {
            Some(ref name) => DisplayName::parse(name)
                .map_err(|e| AppError::Validation(e.to_string()))?,
            None => DisplayName::parse("Anonymous")
                .map_err(|e| AppError::Validation(e.to_string()))?,
        };

        Ok((email, display_name))
    }
}
