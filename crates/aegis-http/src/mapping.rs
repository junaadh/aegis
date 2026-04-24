use aegis_app::{AuthResult, GuestAuthResult, IdentityResult, LoginOutcome};
use aegis_core::{Guest, User};
use aegis_types::{
    AuthResponse, GuestResponse, IdentityData, IdentityResponse, SessionInfo,
    UserResponse,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

fn format_ts(ts: OffsetDateTime) -> String {
    ts.format(&time::format_description::well_known::Iso8601::DEFAULT)
        .unwrap_or_default()
}

pub fn user_to_response(user: &User, roles: Vec<String>) -> UserResponse {
    UserResponse {
        id: user.id.as_uuid(),
        email: user.email.as_str().to_owned(),
        display_name: user.display_name.as_str().to_owned(),
        status: format!("{:?}", user.status).to_lowercase(),
        email_verified: user.is_email_verified(),
        roles,
        metadata: serde_json::Value::Null,
        created_at: format_ts(user.created_at),
        updated_at: format_ts(user.updated_at),
    }
}

pub fn guest_to_response(guest: &Guest) -> GuestResponse {
    GuestResponse {
        id: guest.id.as_uuid(),
        email: guest.email.as_ref().map(|e| e.as_str().to_owned()),
        status: format!("{:?}", guest.status).to_lowercase(),
        expires_at: format_ts(guest.expires_at),
    }
}

pub fn map_identity_result(result: &IdentityResult) -> IdentityResponse {
    match (&result.user, &result.guest) {
        (Some(user), None) => {
            let roles: Vec<String> = result
                .roles
                .iter()
                .map(|r| r.name.as_str().to_owned())
                .collect();
            IdentityResponse {
                kind: "user".to_owned(),
                data: IdentityData::User(user_to_response(user, roles)),
            }
        }
        (None, Some(guest)) => IdentityResponse {
            kind: "guest".to_owned(),
            data: IdentityData::Guest(guest_to_response(guest)),
        },
        _ => IdentityResponse {
            kind: "unknown".to_owned(),
            data: IdentityData::Guest(GuestResponse {
                id: uuid::Uuid::nil(),
                email: None,
                status: "unknown".to_owned(),
                expires_at: String::new(),
            }),
        },
    }
}

pub fn map_auth_result(result: &AuthResult) -> AuthResponse {
    let identity = IdentityResponse {
        kind: "user".to_owned(),
        data: IdentityData::User(UserResponse {
            id: result.user.id.as_uuid(),
            email: result.user.email.as_str().to_owned(),
            display_name: result.user.display_name.as_str().to_owned(),
            status: format!("{:?}", result.user.status).to_lowercase(),
            email_verified: result.user.is_email_verified(),
            roles: vec![],
            metadata: serde_json::Value::Null,
            created_at: format_ts(result.user.created_at),
            updated_at: format_ts(result.user.updated_at),
        }),
    };

    AuthResponse {
        identity,
        session: SessionInfo {
            expires_at: format_ts(result.session_expires_at),
            mfa_verified: result.mfa_verified,
        },
    }
}

pub fn map_guest_auth_result(result: &GuestAuthResult) -> AuthResponse {
    let identity = IdentityResponse {
        kind: "guest".to_owned(),
        data: IdentityData::Guest(guest_to_response(&result.guest)),
    };

    AuthResponse {
        identity,
        session: SessionInfo {
            expires_at: format_ts(result.session_expires_at),
            mfa_verified: false,
        },
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum LoginOutcomeResponse {
    Authenticated(Box<AuthResponse>),
    RequiresMfa { session: SessionInfo },
}

pub fn map_login_outcome(outcome: &LoginOutcome) -> LoginOutcomeResponse {
    match outcome {
        LoginOutcome::Authenticated(auth) => {
            LoginOutcomeResponse::Authenticated(Box::new(map_auth_result(auth)))
        }
        LoginOutcome::RequiresMfa {
            session_expires_at, ..
        } => LoginOutcomeResponse::RequiresMfa {
            session: SessionInfo {
                expires_at: format_ts(*session_expires_at),
                mfa_verified: false,
            },
        },
    }
}
