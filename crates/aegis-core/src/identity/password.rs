use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordPolicy {
    pub min_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digit: bool,
    pub require_symbol: bool,
    pub disallow_common: bool,
    pub disallow_email_substring: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 12,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_symbol: true,
            disallow_common: true,
            disallow_email_substring: true,
        }
    }
}

impl PasswordPolicy {
    pub fn validate(
        &self,
        password: &str,
        email: Option<&str>,
    ) -> Result<(), Vec<PasswordViolation>> {
        let mut violations = Vec::new();

        if password.len() < self.min_length {
            violations.push(PasswordViolation::TooShort {
                min: self.min_length,
                actual: password.len(),
            });
        }

        if self.require_uppercase
            && !password.chars().any(|c| c.is_ascii_uppercase())
        {
            violations.push(PasswordViolation::MissingUppercase);
        }

        if self.require_lowercase
            && !password.chars().any(|c| c.is_ascii_lowercase())
        {
            violations.push(PasswordViolation::MissingLowercase);
        }

        if self.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
            violations.push(PasswordViolation::MissingDigit);
        }

        if self.require_symbol
            && !password.chars().any(|c| !c.is_ascii_alphanumeric())
        {
            violations.push(PasswordViolation::MissingSymbol);
        }

        if let Some(email) = email
            && self.disallow_email_substring
        {
            let email_lower = email.to_ascii_lowercase();
            let local_part = email_lower.split('@').next().unwrap_or("");
            if password.to_ascii_lowercase().contains(local_part) {
                violations.push(PasswordViolation::ContainsEmailSubstring);
            }
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordViolation {
    TooShort { min: usize, actual: usize },
    MissingUppercase,
    MissingLowercase,
    MissingDigit,
    MissingSymbol,
    TooCommon,
    ContainsEmailSubstring,
}

impl fmt::Display for PasswordViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { min, actual } => {
                write!(f, "password is too short ({actual}/{min} characters)")
            }
            Self::MissingUppercase => {
                f.write_str("password must contain an uppercase letter")
            }
            Self::MissingLowercase => {
                f.write_str("password must contain a lowercase letter")
            }
            Self::MissingDigit => f.write_str("password must contain a digit"),
            Self::MissingSymbol => {
                f.write_str("password must contain a symbol")
            }
            Self::TooCommon => f.write_str("password is too common"),
            Self::ContainsEmailSubstring => {
                f.write_str("password must not contain email local part")
            }
        }
    }
}

impl std::error::Error for PasswordViolation {}
