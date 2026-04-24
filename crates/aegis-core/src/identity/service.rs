use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{EffectivePermissions, ParsePermissionError, Permission};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServicePrincipal {
    pub subject: String,
    pub permissions: EffectivePermissions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ServiceTokenScope(Permission);

impl ServiceTokenScope {
    pub const fn permission(self) -> Permission {
        self.0
    }

    pub fn as_str(self) -> &'static str {
        self.0.name().unwrap_or("<invalid-scope>")
    }
}

impl From<Permission> for ServiceTokenScope {
    fn from(value: Permission) -> Self {
        Self(value)
    }
}

impl From<ServiceTokenScope> for Permission {
    fn from(value: ServiceTokenScope) -> Self {
        value.0
    }
}

impl FromStr for ServiceTokenScope {
    type Err = ParseServiceTokenScopeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(
            s.parse().map_err(ParseServiceTokenScopeError::Invalid)?,
        ))
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ParseServiceTokenScopeError {
    #[error("invalid service token scope: {0}")]
    Invalid(ParsePermissionError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtClaims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub typ: String,
    pub scp: Vec<String>,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
}

impl JwtClaims {
    pub fn new_service<I>(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        subject: impl Into<String>,
        scopes: I,
        issued_at: OffsetDateTime,
        expires_at: OffsetDateTime,
        jti: Uuid,
    ) -> Self
    where
        I: IntoIterator<Item = ServiceTokenScope>,
    {
        Self {
            iss: issuer.into(),
            aud: audience.into(),
            sub: subject.into(),
            typ: "service".to_owned(),
            scp: scopes
                .into_iter()
                .map(|scope| scope.as_str().to_owned())
                .collect(),
            iat: issued_at.unix_timestamp(),
            exp: expires_at.unix_timestamp(),
            jti: jti.to_string(),
        }
    }

    pub fn service_principal(
        &self,
    ) -> Result<ServicePrincipal, ServiceAuthError> {
        if self.typ != "service" {
            return Err(ServiceAuthError::UnsupportedType(self.typ.clone()));
        }

        if !self.sub.starts_with("service:") {
            return Err(ServiceAuthError::InvalidSubject(self.sub.clone()));
        }

        let mut permissions = EffectivePermissions::empty();
        for scope in &self.scp {
            let scope =
                scope.parse::<ServiceTokenScope>().map_err(
                    |err| match err {
                        ParseServiceTokenScopeError::Invalid(source) => {
                            ServiceAuthError::InvalidScope {
                                scope: scope.clone(),
                                source,
                            }
                        }
                    },
                )?;
            permissions = permissions.insert(scope.permission());
        }

        Ok(ServicePrincipal {
            subject: self.sub.clone(),
            permissions,
        })
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ServiceAuthError {
    #[error("invalid service subject: {0}")]
    InvalidSubject(String),
    #[error("unsupported service token type: {0}")]
    UnsupportedType(String),
    #[error("invalid service token scope '{scope}': {source}")]
    InvalidScope {
        scope: String,
        source: ParsePermissionError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AdminReadUser, AuditReadAuditLog};

    #[test]
    fn service_claims_map_scopes_into_permissions() {
        let claims = JwtClaims::new_service(
            "aegis",
            "aegis-internal",
            "service:dashboard",
            [
                ServiceTokenScope::from(AdminReadUser::permission()),
                ServiceTokenScope::from(AuditReadAuditLog::permission()),
            ],
            OffsetDateTime::now_utc(),
            OffsetDateTime::now_utc(),
            Uuid::nil(),
        );

        let principal = claims.service_principal().unwrap();

        assert_eq!(principal.subject, "service:dashboard");
        assert!(principal.permissions.has(AdminReadUser::permission()));
        assert!(principal.permissions.has(AuditReadAuditLog::permission()));
    }

    #[test]
    fn invalid_scope_fails_claim_mapping() {
        let claims = JwtClaims {
            iss: "aegis".to_owned(),
            aud: "aegis-internal".to_owned(),
            sub: "service:dashboard".to_owned(),
            typ: "service".to_owned(),
            scp: vec!["admin:read:nope".to_owned()],
            iat: 1,
            exp: 2,
            jti: Uuid::nil().to_string(),
        };

        assert!(matches!(
            claims.service_principal(),
            Err(ServiceAuthError::InvalidScope { .. })
        ));
    }
}
