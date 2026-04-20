#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum UserStatus {
    Active,
    Disabled,
    #[default]
    PendingVerification,
    Deleted,
}

impl UserStatus {
    #[inline]
    pub const fn can_authenticate(&self) -> bool {
        matches!(self, Self::Active)
    }

    #[inline]
    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }

    #[inline]
    pub const fn is_disabled(&self) -> bool {
        matches!(self, Self::Disabled)
    }

    #[inline]
    pub const fn is_deleted(&self) -> bool {
        matches!(self, Self::Deleted)
    }

    #[inline]
    pub const fn is_pending_verification(&self) -> bool {
        matches!(self, Self::PendingVerification)
    }
}

impl std::fmt::Display for UserStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
            Self::PendingVerification => "pending_verification",
            Self::Deleted => "deleted",
        })
    }
}

impl std::str::FromStr for UserStatus {
    type Err = UserStatusParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "active" => Ok(Self::Active),
            "disabled" => Ok(Self::Disabled),
            "pending_verification" => Ok(Self::PendingVerification),
            "deleted" => Ok(Self::Deleted),
            other => Err(UserStatusParseError::Unknown(other.to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserStatusParseError {
    Unknown(String),
}

impl std::fmt::Display for UserStatusParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown(s) => write!(f, "unknown user status: {s}"),
        }
    }
}

impl std::error::Error for UserStatusParseError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum GuestStatus {
    #[default]
    Active,
    Converted,
    Expired,
}

impl GuestStatus {
    #[inline]
    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }

    #[inline]
    pub const fn can_convert(&self) -> bool {
        matches!(self, Self::Active)
    }

    #[inline]
    pub const fn is_expired(&self) -> bool {
        matches!(self, Self::Expired)
    }

    #[inline]
    pub const fn is_converted(&self) -> bool {
        matches!(self, Self::Converted)
    }
}

impl std::fmt::Display for GuestStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Active => "active",
            Self::Converted => "converted",
            Self::Expired => "expired",
        })
    }
}
