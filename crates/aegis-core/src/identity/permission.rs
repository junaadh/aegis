use paste::paste;
use std::{fmt, marker::PhantomData, str::FromStr};

/// Errors that can occur while parsing permission string
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsePermissionError {
    /// The input did not match the expected `domain:action:resource` shape
    InvalidFormat,
    /// The domain segment is not recognized. Valid domains are variants of [`Domain`]
    InvalidDomain,
    /// The action segment is not recognized. Valid actions are variants of [`Action`]
    InvalidAction,
    /// The resource segment is not recognized. Valid resources are variants of [`Resource`]
    InvalidResource,
    /// The parsed domain, action and resource were individually valid, but
    /// do not form a declared valid permission combination
    InvalidCombination(String),
}

impl fmt::Display for ParsePermissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat => write!(f, "invalid permission format"),
            Self::InvalidDomain => write!(f, "invalid permission domain"),
            Self::InvalidAction => write!(f, "invalid permission action"),
            Self::InvalidResource => write!(f, "invalid permission resource"),
            Self::InvalidCombination(p) => {
                write!(f, "invalid permission combination: {p}")
            }
        }
    }
}

impl std::error::Error for ParsePermissionError {}

/// Marker trait for type-level domain markers.
///
/// Each generated marker maps to exactly one runtime [`Domain`] variant.
pub trait DomainMarker {
    /// The runtime domain represented by this marker type.
    const VALUE: Domain;
}

/// Marker trait for type-level action markers.
///
/// Each generated marker maps to exactly one runtime [`Action`] variant.
pub trait ActionMarker {
    /// The runtime action represented by this marker type.
    const VALUE: Action;
}

/// Marker trait for type-level resource markers.
///
/// Each generated marker maps to exactly one runtime [`Resource`] variant.
pub trait ResourceMarker {
    /// The runtime resource represented by this marker type.
    const VALUE: Resource;
}

/// Proof trait indicating that a `(Domain, Action, Resource)` triple is valid.
///
/// This trait is only implemented for combinations declared in the
/// `permissions { ... }` section of the permission table.
pub trait ValidPermissionTriple<D, A, R>
where
    D: DomainMarker,
    A: ActionMarker,
    R: ResourceMarker,
{
}

/// Maps a valid typed triple to its runtime bit-backed [`Permission`].
///
/// This is the bridge between:
/// - compile-time proof of validity via [`ValidPermissionTriple`]
/// - runtime permission checks using permission bits
pub trait TriplePermission<D, A, R>
where
    D: DomainMarker,
    A: ActionMarker,
    R: ResourceMarker,
    (): ValidPermissionTriple<D, A, R>,
{
    /// The runtime permission bit corresponding to the typed triple.
    const PERMISSION: Permission;
}

/// A typed permission proof token for a valid `(Domain, Action, Resource)` triple.
///
/// This type carries no runtime data. It exists purely to let the type system
/// express and validate permission triples.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TypedPermission<D, A, R>
where
    D: DomainMarker,
    A: ActionMarker,
    R: ResourceMarker,
    (): ValidPermissionTriple<D, A, R>,
{
    _marker: PhantomData<(D, A, R)>,
}

impl<D, A, R> TypedPermission<D, A, R>
where
    D: DomainMarker,
    A: ActionMarker,
    R: ResourceMarker,
    (): ValidPermissionTriple<D, A, R>,
{
    /// Creates a new typed permission proof token.
    pub const fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<D, A, R> Default for TypedPermission<D, A, R>
where
    D: DomainMarker,
    A: ActionMarker,
    R: ResourceMarker,
    (): ValidPermissionTriple<D, A, R>,
{
    fn default() -> Self {
        Self::new()
    }
}

/// Trait implemented by each generated named permission type.
///
/// A named permission is the primary ergonomic API for permission usage:
///
/// - `IdentityReadEmail::permission()`
/// - `perms.require_named::<IdentityReadEmail>()`
pub trait NamedPermission {
    /// The domain marker for this named permission.
    type D: DomainMarker;
    /// The action marker for this named permission.
    type A: ActionMarker;
    /// The resource marker for this named permission.
    type R: ResourceMarker;

    /// The canonical wire name, such as `identity:read:email`.
    const NAME: &'static str;

    /// The runtime bit-backed permission value.
    const PERMISSION: Permission;
}

macro_rules! define_string_enum {
    (
        $(#[$meta:meta])*
        pub enum $Enum:ident {
            $(
                $(#[$variant_meta:meta])*
                $Variant:ident => $wire:literal
            ),+ $(,)?
        }
        parse_error = $parse_error:expr;
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $Enum {
            $(
                #[doc = "Wire value: `"]
                #[doc = $wire]
                #[doc = "`."]
                $(#[$variant_meta])*
                $Variant
            ),+
        }

        impl $Enum {
            #[doc = "Returns the canonical wire string for this `"]
            #[doc = stringify!($Enum)]
            #[doc = "` variant."]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$Variant => $wire),+
                }
            }
        }

        impl FromStr for $Enum {
            type Err = ParsePermissionError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $($wire => Ok(Self::$Variant),)+
                    _ => Err($parse_error)
                }
            }
        }

        impl fmt::Display for $Enum {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(match self {
                    $(Self::$Variant => $wire),+
                })
            }
        }
    };
}

macro_rules! count_idents {
    ($($idents:ident),* $(,)?) => {
        <[()]>::len(&[$(count_idents!(@one $idents)),*])
    };

    (@one $ident:ident) => {()};
}

macro_rules! define_permissions {
    (
        domains {
            $($DomainVariant:ident => $domain_wire:literal),+ $(,)?
        }

        actions {
            $($ActionVariant:ident => $action_wire:literal),+ $(,)?
        }

        resources {
            $($ResourceVariant:ident => $resource_wire:literal),+ $(,)?
        }

        permissions {
            $($PermissionAlias:ident => ($PD:ident, $PA:ident, $PR:ident)),+ $(,)?
        }
    ) => {
        macro_rules! __domain_wire {
            $( ($DomainVariant) => { $domain_wire }; )+
        }

        macro_rules! __action_wire {
            $( ($ActionVariant) => { $action_wire }; )+
        }

        macro_rules! __resource_wire {
            $( ($ResourceVariant) => { $resource_wire }; )+
        }

        define_string_enum! {
            /// Top-level permission domains.
            ///
            /// A domain identifies the broad subsystem a permission belongs to,
            /// such as identity, session, or audit.
            pub enum Domain {
                $(
                    #[doc = "Domain variant `"]
                    #[doc = stringify!($DomainVariant)]
                    #[doc = "`."]
                    $DomainVariant => $domain_wire
                ),+
            }
            parse_error = ParsePermissionError::InvalidDomain;
        }

        define_string_enum! {
            /// Permission actions.
            ///
            /// An action describes the kind of operation permitted within a domain.
            pub enum Action {
                $(
                    #[doc = "Action variant `"]
                    #[doc = stringify!($ActionVariant)]
                    #[doc = "`."]
                    $ActionVariant => $action_wire
                ),+
            }
            parse_error = ParsePermissionError::InvalidAction;
        }

        define_string_enum! {
            /// Permission resources.
            ///
            /// A resource identifies the specific target object of a permission.
            pub enum Resource {
                $(
                    #[doc = "Resource variant `"]
                    #[doc = stringify!($ResourceVariant)]
                    #[doc = "`."]
                    $ResourceVariant => $resource_wire
                ),+
            }
            parse_error = ParsePermissionError::InvalidResource;
        }

        /// A single valid runtime permission represented as a one-hot bit.
        ///
        /// Each declared permission occupies exactly one bit within a `u128`.
        /// This makes permission checks fast and allocation-free.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct Permission(u128);

        impl Permission {
            /// Creates a permission from a dense bit index.
            pub const fn from_index(index: u32) -> Self {
                Self(1u128 << index)
            }

            /// Returns the raw one-hot bit representation
            pub const fn bits(self) -> u128 {
                self.0
            }

            /// Returns `true` if this permission contains exactly one bit
            pub const fn is_single_bit(self) -> bool {
                self.0 != 0 && (self.0 & (self.0 - 1)) == 0
            }

            pub const fn index(self) -> Option<u32> {
                if !self.is_single_bit() {
                    return None;
                }

                let mut i = 0u32;
                while i < 128 {
                    if self.0 == (1u128 << i) {
                        return Some(i)
                    }
                    i += 1;
                }

                None
            }

            /// Returns metadata for this permission, if it is a valid declared permission
            pub const fn info(self) -> Option<PermissionInfo> {
                match self.index() {
                    Some(i) if (i as usize) < ALL_VALID_PERMISSION_INFOS.len() => {
                        Some(ALL_VALID_PERMISSION_INFOS[i as usize])
                    },
                    _ => None,
                }
            }

            /// Returns the canonical wire name for this permission, if valid
            pub const fn name(self) -> Option<&'static str> {
                match self.index() {
                    Some(i) if (i as usize) < ALL_VALID_PERMISSION_NAMES.len() => {
                        Some(ALL_VALID_PERMISSION_NAMES[i as usize])
                    },
                    _ => None,
                }
            }

            /// Returns `true` if this permission is one of the declared valid permissions
            pub const fn is_valid_combination(&self) -> bool {
                match self.index() {
                    Some(i) if (i as usize) < ALL_VALID_PERMISSIONS.len() => {
                        ALL_VALID_PERMISSIONS[i as usize].bits() == self.bits()
                    }
                    _ => false,
                }
            }
        }

        impl fmt::Display for Permission {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self.name() {
                    Some(name) => f.write_str(name),
                    None => write!(f, "<invalid-permission:{:#x}>", self.bits()),
                }
            }
        }

        impl FromStr for Permission {
            type Err = ParsePermissionError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let mut parts = s.split(":");

                let domain: Domain = parts
                    .next()
                    .ok_or(ParsePermissionError::InvalidFormat)?
                    .parse()?;

                let action: Action = parts
                    .next()
                    .ok_or(ParsePermissionError::InvalidFormat)?
                    .parse()?;

                let resource: Resource = parts
                    .next()
                    .ok_or(ParsePermissionError::InvalidFormat)?
                    .parse()?;

                let mut i = 0usize;
                while i < ALL_VALID_PERMISSION_INFOS.len() {
                    let info = ALL_VALID_PERMISSION_INFOS[i];
                    if info.domain == domain && info.action == action && info.resource == resource {
                        return Ok(info.permission)
                    }
                    i += 1;
                }

                Err(ParsePermissionError::InvalidCombination(s.to_string()))
            }
        }

        /// Introspection data for a declared permission.
        ///
        /// This type is generated entirely from the permission declaration table.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct PermissionInfo {
            /// The bit-backed permission value.
            pub permission: Permission,
            /// The canonical wire name.
            pub name: &'static str,
            /// The permission domain.
            pub domain: Domain,
            /// The permission action.
            pub action: Action,
            /// The permission resource.
            pub resource: Resource,
        }

        /// Total number of declared valid permissions.
        pub const VALID_PERMISSION_COUNT: usize = count_idents!($($PermissionAlias),+);

        const _: [(); VALID_PERMISSION_COUNT] = [(); count_idents!($($PermissionAlias),+)];

        paste! {
            $(
                #[doc = "Type-level marker for the `"]
                #[doc = $domain_wire]
                #[doc = "` domain."]
                pub enum [<$DomainVariant Domain>]  {}

                impl DomainMarker for [<$DomainVariant Domain>] {
                    const VALUE: Domain = Domain::$DomainVariant;
                }

            )+

            $(
                #[doc = "Type-level marker for the `"]
                #[doc = $action_wire]
                #[doc = "` action."]
                pub enum [<$ActionVariant Action>] {}

                impl ActionMarker for [<$ActionVariant Action>] {
                    const VALUE: Action = Action::$ActionVariant;
                }

            )+

            $(
                #[doc = "Type-level marker for the `"]
                #[doc = $resource_wire]
                #[doc = "` resource."]
                pub enum [<$ResourceVariant Resource>] {}

                impl ResourceMarker for [<$ResourceVariant Resource>] {
                    const VALUE: Resource = Resource::$ResourceVariant;
                }

            )+

            $(
                impl ValidPermissionTriple<[<$PD Domain>], [<$PA Action>], [<$PR Resource>]> for () {}

                #[doc = "Named permission `"]
                #[doc = concat!(
                    __domain_wire!($PD), ":",
                    __action_wire!($PA), ":",
                    __resource_wire!($PR)
                )]
                #[doc = "`."]
                pub struct $PermissionAlias;

                impl $PermissionAlias {
                    #[doc = "Returns the typed proof token for `"]
                    #[doc = concat!(
                        __domain_wire!($PD), ":",
                        __action_wire!($PA), ":",
                        __resource_wire!($PR)
                    )]
                    #[doc = "`."]
                    pub const fn typed() -> TypedPermission<[<$PD Domain>], [<$PA Action>], [<$PR Resource>]> {
                        TypedPermission::new()
                    }

                    #[doc = "Returns the runtime bit-backed permission for `"]
                    #[doc = concat!(
                        __domain_wire!($PD), ":",
                        __action_wire!($PA), ":",
                        __resource_wire!($PR)
                    )]
                    #[doc = "`."]
                    pub const fn permission() -> Permission {
                        Permission::from_index([<$PermissionAlias:upper _INDEX>] as u32)
                    }
                }

                impl NamedPermission for $PermissionAlias {
                    type D = [<$PD Domain>];
                    type A = [<$PA Action>];
                    type R = [<$PR Resource>];

                    const NAME: &'static str = concat!(
                        __domain_wire!($PD), ":",
                        __action_wire!($PA), ":",
                        __resource_wire!($PR)
                    );

                    const PERMISSION: Permission =
                        Permission::from_index([<$PermissionAlias:upper _INDEX>] as u32);
                }

                impl TriplePermission<[<$PD Domain>], [<$PA Action>], [<$PR Resource>]> for () {
                    const PERMISSION: Permission =
                        Permission::from_index([<$PermissionAlias:upper _INDEX>] as u32);
                }
            )+
        }

        /// Dense index assigned to each declared valid permission.
        ///
        /// The numeric value of each variant determines the bit position used
        /// by the runtime [`Permission`] representation.
        #[repr(u8)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum PermissionIndex {
            $($PermissionAlias),+
        }

        paste! {
            $(
                #[doc = "Dense bit index for `"]
                #[doc = stringify!($PermissionAlias)]
                #[doc = "`."]
                pub const [<$PermissionAlias:upper _INDEX>]: usize =
                    PermissionIndex::$PermissionAlias as usize;
            )+
        }

        // All declared valid runtime permissions in dense index order.
        pub const ALL_VALID_PERMISSIONS: [Permission; VALID_PERMISSION_COUNT] = [
            $($PermissionAlias::permission()),+
        ];

        /// All canonical wire names in dense index order.
        pub const ALL_VALID_PERMISSION_NAMES: [&str; VALID_PERMISSION_COUNT] = [
            $(<$PermissionAlias as NamedPermission>::NAME),+
        ];

        /// All permission metadata in dense index order.
        pub const ALL_VALID_PERMISSION_INFOS: [PermissionInfo; VALID_PERMISSION_COUNT] = [
            $(
                PermissionInfo {
                    permission: $PermissionAlias::permission(),
                    name: <$PermissionAlias as NamedPermission>::NAME,
                    domain: Domain::$PD,
                    action: Action::$PA,
                    resource: Resource::$PR,
                }
            ),+
        ];

        paste! {
            $(
                const _: TypedPermission<[<$PD Domain>], [<$PA Action>], [<$PR Resource>]> =
                    $PermissionAlias::typed();
            )+
        }

        const _: () = {
            assert!(VALID_PERMISSION_COUNT <= 128);
        };
    };

}

define_permissions! {
    domains {
        Identity => "identity",
        Session => "session",
        Credential => "credential",
        Mfa => "mfa",
        Audit => "audit",
        Webhook => "webhook",
        Admin => "admin",
    }

    actions {
        Read => "read",
        Create => "create",
        Update => "update",
        Delete => "delete",
        Validate => "validate",
        Revoke => "revoke",
        Manage => "manage",
    }

        resources {
            User => "user",
            Guest => "guest",
            System => "system",
            Email => "email",
            Profile => "profile",
        Roles => "roles",
        Status => "status",
        Token => "token",
        Session => "session",
        Password => "password",
        Passkey => "passkey",
        Totp => "totp",
        RecoveryCode => "recovery_code",
        AuditLog => "audit_log",
        Webhook => "webhook",
    }

    permissions {
        IdentityReadUser => (Identity, Read, User),
        IdentityReadGuest => (Identity, Read, Guest),
        IdentityReadEmail => (Identity, Read, Email),
        IdentityReadProfile => (Identity, Read, Profile),
        IdentityReadRoles => (Identity, Read, Roles),
        IdentityReadStatus => (Identity, Read, Status),

        SessionValidateToken => (Session, Validate, Token),
        SessionReadSession => (Session, Read, Session),
        SessionRevokeSession => (Session, Revoke, Session),

        CredentialReadPassword => (Credential, Read, Password),
        CredentialReadPasskey => (Credential, Read, Passkey),
        CredentialRevokePassword => (Credential, Revoke, Password),
        CredentialRevokePasskey => (Credential, Revoke, Passkey),

        MfaManageTotp => (Mfa, Manage, Totp),
        MfaManageRecoveryCode => (Mfa, Manage, RecoveryCode),
        MfaRevokeTotp => (Mfa, Revoke, Totp),

        AuditReadAuditLog => (Audit, Read, AuditLog),

        WebhookManageWebhook => (Webhook, Manage, Webhook),

        AdminDeleteUser => (Admin, Delete, User),
        AdminManageRoles => (Admin, Manage, Roles),
        AdminManageWebhook => (Admin, Manage, Webhook),
        AdminReadSystem => (Admin, Read, System),
        AdminReadUser => (Admin, Read, User),
        AdminUpdateUser => (Admin, Update, User),
    }
}

#[derive(Debug, Clone)]
pub enum AuthzError {
    Forbidden(Permission),
}

impl fmt::Display for AuthzError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthzError::Forbidden(p) => write!(f, "missing permission: {}", p),
        }
    }
}

impl std::error::Error for AuthzError {}

/// A set of effective permissions represented as a `u128` bitset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct EffectivePermissions {
    bits: u128,
}

impl EffectivePermissions {
    /// Creates an empty permission set.
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Creates a permission set from raw bits.
    pub const fn from_bits(bits: u128) -> Self {
        Self { bits }
    }

    /// Creates a permission set from a single permission.
    pub const fn singleton(permission: Permission) -> Self {
        Self {
            bits: permission.bits(),
        }
    }

    /// Creates a permission set containing the given named permission.
    pub fn from_named<P: NamedPermission>() -> Self {
        Self::singleton(P::PERMISSION)
    }

    /// Creates a permission set from an iterator of permissions.
    pub fn new<I>(permissions: I) -> Self
    where
        I: IntoIterator<Item = Permission>,
    {
        let mut bits = 0u128;
        for p in permissions {
            bits |= p.bits();
        }
        Self { bits }
    }

    /// Returns `true` if the bits is zero, or empty permission set
    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }

    /// Returns the raw bitset.
    pub const fn bits(self) -> u128 {
        self.bits
    }

    /// Returns a new set with the given permission inserted.
    pub const fn insert(mut self, permission: Permission) -> Self {
        self.bits |= permission.bits();
        self
    }

    /// Returns a new set with the given permission removed.
    pub const fn remove(mut self, permission: Permission) -> Self {
        self.bits &= !permission.bits();
        self
    }

    /// Returns the union of two permission sets.
    pub const fn union(self, other: Self) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }

    /// Returns the intersection of two permission sets.
    pub const fn intersection(self, other: Self) -> Self {
        Self {
            bits: self.bits & other.bits,
        }
    }

    /// Returns a declarative `Iterator<Item = Permission>` from the effective set permission bits
    pub fn iter(self) -> impl Iterator<Item = Permission> {
        let mut bits = self.bits();

        std::iter::from_fn(move || {
            if bits == 0 {
                return None;
            }

            let idx = bits.trailing_zeros();
            bits &= bits - 1;
            Some(Permission::from_index(idx))
        })
    }

    /// Returns `true` if this set contains the given permission.
    pub const fn has(self, permission: Permission) -> bool {
        (self.bits & permission.bits()) == permission.bits()
    }

    /// Returns `true` if this set contains all permissions present in `other`.
    pub const fn contains_all(self, other: Self) -> bool {
        (self.bits & other.bits) == other.bits
    }

    /// Returns `true` if this set contains any permission present in `other`.
    pub const fn contains_any(self, other: Self) -> bool {
        (self.bits & other.bits) != 0
    }

    /// Returns `true` if this set contains the permission corresponding to the typed triple.
    pub fn has_typed<D, A, R>(&self, _: TypedPermission<D, A, R>) -> bool
    where
        D: DomainMarker,
        A: ActionMarker,
        R: ResourceMarker,
        (): ValidPermissionTriple<D, A, R> + TriplePermission<D, A, R>,
    {
        self.has(<() as TriplePermission<D, A, R>>::PERMISSION)
    }

    /// Requires the permission corresponding to the typed triple.
    pub fn require_typed<D, A, R>(
        &self,
        _: TypedPermission<D, A, R>,
    ) -> Result<(), AuthzError>
    where
        D: DomainMarker,
        A: ActionMarker,
        R: ResourceMarker,
        (): ValidPermissionTriple<D, A, R> + TriplePermission<D, A, R>,
    {
        let permission = <() as TriplePermission<D, A, R>>::PERMISSION;
        if self.has(permission) {
            Ok(())
        } else {
            Err(AuthzError::Forbidden(permission))
        }
    }

    /// Returns `true` if this set contains the given named permission.
    pub fn has_named<P: NamedPermission>(&self) -> bool {
        self.has(P::PERMISSION)
    }

    /// Requires the given named permission.
    pub fn require_named<P: NamedPermission>(&self) -> Result<(), AuthzError> {
        if self.has_named::<P>() {
            Ok(())
        } else {
            Err(AuthzError::Forbidden(P::PERMISSION))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_permission_names_roundtrip() {
        for (perm, name) in ALL_VALID_PERMISSIONS
            .iter()
            .zip(ALL_VALID_PERMISSION_NAMES.iter())
        {
            let parsed: Permission = name.parse().unwrap();
            assert_eq!(*perm, parsed);
        }
    }

    #[test]
    fn infos_align_with_names_and_permissions() {
        for i in 0..VALID_PERMISSION_COUNT {
            assert_eq!(
                ALL_VALID_PERMISSION_INFOS[i].name,
                ALL_VALID_PERMISSION_NAMES[i]
            );
            assert_eq!(
                ALL_VALID_PERMISSION_INFOS[i].permission,
                ALL_VALID_PERMISSIONS[i]
            );
        }
    }

    #[test]
    fn all_permissions_are_single_bit() {
        for p in ALL_VALID_PERMISSIONS {
            assert!(p.is_single_bit());
        }
    }
}
