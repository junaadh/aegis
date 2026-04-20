mod passkey;
mod password;
mod recovery_code;
mod totp;

pub use passkey::*;
pub use password::*;
pub use recovery_code::*;
pub use totp::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialKind {
    Password,
    Passkey,
    Totp,
}

impl std::fmt::Display for CredentialKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Password => "password",
            Self::Passkey => "passkey",
            Self::Totp => "totp",
        })
    }
}
