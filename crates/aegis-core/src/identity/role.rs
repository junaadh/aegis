use std::{fmt, str::FromStr};

use crate::{
    identity::{EffectivePermissions, NamedPermission, Permission},
    ids::{RoleId, UserId},
};
use time::OffsetDateTime;

/// Human-assigned role definition.
///
/// A role is declarative: it names a set of permissions.
/// It does not store the optimized evaluated bitset directly as its source of truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Role {
    pub id: RoleId,
    pub name: RoleName,
    pub description: Option<String>,
    permissions: EffectivePermissions,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl Role {
    pub fn new(
        id: RoleId,
        name: RoleName,
        description: Option<String>,
        permissions: EffectivePermissions,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
    ) -> Result<Self, RoleError> {
        if permissions.is_empty() {
            return Err(RoleError::EmptyPermissions);
        }

        Ok(Self {
            id,
            name,
            description,
            permissions,
            created_at,
            updated_at,
        })
    }

    pub fn from_permissions<I>(
        id: RoleId,
        name: RoleName,
        description: Option<String>,
        permission: I,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
    ) -> Result<Self, RoleError>
    where
        I: IntoIterator<Item = Permission>,
    {
        let permissions = EffectivePermissions::new(permission);
        Self::new(id, name, description, permissions, created_at, updated_at)
    }

    /// Returns the effective permission bitset for this role.
    pub const fn effective_permissions(&self) -> EffectivePermissions {
        self.permissions
    }

    /// Iterates over all granted permissions without allocating.
    pub fn iter_permissions(&self) -> impl Iterator<Item = Permission> {
        self.permissions.iter()
    }

    /// Returns a declarative `Vec<Permission>` view of the role permissions.
    pub fn permissions_vec(&self) -> Vec<Permission> {
        self.permissions.iter().collect()
    }

    /// Returns true if this role grants the given permission.
    pub const fn grants(&self, permission: Permission) -> bool {
        self.permissions.has(permission)
    }

    /// Returns true if this role grants the given named permission.
    pub const fn grants_named<P>(&self) -> bool
    where
        P: NamedPermission,
    {
        self.permissions.has(P::PERMISSION)
    }

    /// Repplaces the full permission set for this role
    pub fn replace_permissions(
        &mut self,
        permissions: EffectivePermissions,
    ) -> Result<(), RoleError> {
        if permissions.is_empty() {
            return Err(RoleError::EmptyPermissions);
        }

        self.permissions = permissions;
        self.updated_at = OffsetDateTime::now_utc();
        Ok(())
    }

    /// Replaces the full permission set for this role from a declarative iterator
    pub fn replace_permissions_from<I>(
        &mut self,
        permissions: I,
    ) -> Result<(), RoleError>
    where
        I: IntoIterator<Item = Permission>,
    {
        let permissions = EffectivePermissions::new(permissions);
        self.replace_permissions(permissions)
    }

    /// Adds a permission to this role
    pub fn add_permission(&mut self, permission: Permission) {
        let next = self.permissions.insert(permission);

        if next != self.permissions {
            self.permissions = next;
            self.updated_at = OffsetDateTime::now_utc();
        }
    }

    /// Removes a permission from this role
    pub fn remove_permission(
        &mut self,
        permission: Permission,
    ) -> Result<(), RoleError> {
        let next = self.permissions.remove(permission);

        if next.is_empty() {
            return Err(RoleError::EmptyPermissions);
        }

        if next != self.permissions {
            self.permissions = next;
            self.updated_at = OffsetDateTime::now_utc();
        }

        Ok(())
    }
}

/// Assignment of a role to a user.
///
/// This is separate from [`Role`] so that role definitions remain reusable,
/// while assignments can carry grant metadata and expiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRoleAssignment {
    pub user_id: UserId,
    pub role_id: RoleId,
    pub granted_at: OffsetDateTime,
    pub expires_at: Option<OffsetDateTime>,
}

impl UserRoleAssignment {
    pub fn is_active_at(&self, now: OffsetDateTime) -> bool {
        match self.expires_at {
            Some(expires_at) => expires_at > now,
            None => true,
        }
    }

    pub fn is_active_now(&self) -> bool {
        self.is_active_at(OffsetDateTime::now_utc())
    }
}

/// Canonical role name.
///
/// Keeps role naming rules out of handlers and DB code.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RoleName(String);

impl RoleName {
    pub fn parse(input: impl AsRef<str>) -> Result<Self, RoleNameError> {
        input.as_ref().parse()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for RoleName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for RoleName {
    type Err = RoleNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();

        if trimmed.is_empty() {
            return Err(RoleNameError::Empty);
        }

        if trimmed.len() > 64 {
            return Err(RoleNameError::TooLong);
        }

        if !trimmed.chars().all(|x| {
            x.is_ascii_lowercase() || x.is_ascii_digit() || x == '_' || x == '-'
        }) {
            return Err(RoleNameError::InvalidCharacters);
        }

        Ok(Self(trimmed.to_owned()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleError {
    EmptyPermissions,
}

impl fmt::Display for RoleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPermissions => {
                f.write_str("role must contain atleast one permission")
            }
        }
    }
}

impl std::error::Error for RoleError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleNameError {
    Empty,
    TooLong,
    InvalidCharacters,
}

impl fmt::Display for RoleNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("role name cannot be empty"),
            Self::TooLong => f.write_str("role name is too long"),
            Self::InvalidCharacters => f.write_str("role name may only container lowercase ascii letters, digits, '_' and '-'"),
        }
    }
}

impl std::error::Error for RoleNameError {}

pub trait RolePermissionDedup {
    fn dedup_perms(&self) -> Vec<Permission>;
}

impl<T> RolePermissionDedup for T
where
    for<'a> &'a T: IntoIterator<Item = &'a Permission>,
{
    fn dedup_perms(&self) -> Vec<Permission> {
        let iter = self.into_iter();
        let mut out = Vec::with_capacity(iter.size_hint().0);
        let mut seen = EffectivePermissions::empty();

        for &perm in iter {
            if !seen.has(perm) {
                seen = seen.insert(perm);
                out.push(perm);
            }
        }

        out
    }
}

pub trait RolePermissionAggragate {
    fn aggregate_role_perms(&self) -> EffectivePermissions;
}

impl<T> RolePermissionAggragate for T
where
    for<'a> &'a T: IntoIterator<Item = &'a Role>,
{
    fn aggregate_role_perms(&self) -> EffectivePermissions {
        let mut out = EffectivePermissions::empty();

        for role in self.into_iter() {
            out = out.union(role.effective_permissions());
        }

        out
    }
}
