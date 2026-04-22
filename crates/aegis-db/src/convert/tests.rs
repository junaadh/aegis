use time::OffsetDateTime;
use uuid::Uuid;

use aegis_core::{Actor, PendingTokenPurpose, RecoveryCodeState, TotpAlgorithm};
use crate::error::ConversionError;
use crate::row::{
    AuditLogRow, EmailVerificationTokenRow, GuestRow, PasswordCredentialRow,
    PasswordResetTokenRow, RecoveryCodeRow, SessionRow, TotpCredentialRow, UserRoleAssignmentRow,
    UserRow,
};

fn uuid(i: u8) -> Uuid {
    let mut bytes = [0u8; 16];
    bytes[0] = i;
    Uuid::from_bytes(bytes)
}

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

#[test]
fn user_row_active_conversion() {
    let row = UserRow {
        id: uuid(1),
        email: "test@example.com".to_owned(),
        email_verified_at: Some(now()),
        display_name: "Test User".to_owned(),
        status: "active".to_owned(),
        metadata: serde_json::json!({}),
        created_at: now(),
        updated_at: now(),
        deleted_at: None,
    };

    let user: aegis_core::User = row.try_into().unwrap();
    assert_eq!(user.id.as_uuid(), uuid(1));
    assert_eq!(user.email.as_str(), "test@example.com");
    assert!(user.is_email_verified());
    assert!(user.is_active());
}

#[test]
fn user_row_pending_verification() {
    let row = UserRow {
        id: uuid(2),
        email: "pending@example.com".to_owned(),
        email_verified_at: None,
        display_name: "Pending".to_owned(),
        status: "pending_verification".to_owned(),
        metadata: serde_json::json!({"k":"v"}),
        created_at: now(),
        updated_at: now(),
        deleted_at: None,
    };

    let user: aegis_core::User = row.try_into().unwrap();
    assert!(!user.is_email_verified());
    assert!(user.status.is_pending_verification());
    assert_eq!(user.metadata.as_str(), r#"{"k":"v"}"#);
}

#[test]
fn user_row_deleted_with_timestamp() {
    let ts = now();
    let row = UserRow {
        id: uuid(3),
        email: "deleted@example.com".to_owned(),
        email_verified_at: None,
        display_name: "Deleted".to_owned(),
        status: "deleted".to_owned(),
        metadata: serde_json::json!({}),
        created_at: now(),
        updated_at: now(),
        deleted_at: Some(ts),
    };

    let user: aegis_core::User = row.try_into().unwrap();
    assert!(user.is_deleted());
    assert_eq!(user.deleted_at, Some(ts));
}

#[test]
fn user_row_invalid_status() {
    let row = UserRow {
        id: uuid(4),
        email: "bad@example.com".to_owned(),
        email_verified_at: None,
        display_name: "Bad Status".to_owned(),
        status: "invalid_status".to_owned(),
        metadata: serde_json::json!({}),
        created_at: now(),
        updated_at: now(),
        deleted_at: None,
    };

    let result: Result<aegis_core::User, ConversionError> = row.try_into();
    assert!(result.is_err());
    match result.unwrap_err() {
        ConversionError::InvalidStatus(s) => assert_eq!(s, "invalid_status"),
        e => panic!("expected InvalidStatus, got {e}"),
    }
}

#[test]
fn user_row_invalid_email() {
    let row = UserRow {
        id: uuid(5),
        email: "not-an-email".to_owned(),
        email_verified_at: None,
        display_name: "Bad Email".to_owned(),
        status: "active".to_owned(),
        metadata: serde_json::json!({}),
        created_at: now(),
        updated_at: now(),
        deleted_at: None,
    };

    let result: Result<aegis_core::User, ConversionError> = row.try_into();
    assert!(result.is_err());
}

#[test]
fn guest_row_conversion() {
    let row = GuestRow {
        id: uuid(10),
        email: Some("guest@example.com".to_owned()),
        metadata: serde_json::json!({"source":"web"}),
        created_at: now(),
        updated_at: now(),
        converted_to: None,
        expires_at: now() + time::Duration::days(30),
    };

    let guest: aegis_core::Guest = row.try_into().unwrap();
    assert_eq!(guest.email.as_ref().unwrap().as_str(), "guest@example.com");
    assert!(guest.converted_to.is_none());
    assert!(guest.status.is_active());
}

#[test]
fn guest_row_converted() {
    let row = GuestRow {
        id: uuid(11),
        email: None,
        metadata: serde_json::json!({}),
        created_at: now(),
        updated_at: now(),
        converted_to: Some(uuid(99)),
        expires_at: now(),
    };

    let guest: aegis_core::Guest = row.try_into().unwrap();
    assert_eq!(guest.converted_to.unwrap().as_uuid(), uuid(99));
    assert!(guest.status.is_converted());
}

#[test]
fn session_row_user_identity() {
    let token_hash = vec![0u8; 32];
    let row = SessionRow {
        id: uuid(20),
        token_hash: token_hash.clone(),
        user_id: Some(uuid(1)),
        guest_id: None,
        expires_at: now() + time::Duration::hours(24),
        last_seen_at: now(),
        mfa_verified: false,
        user_agent: Some("test".to_owned()),
        ip_address: Some("127.0.0.1".to_owned()),
        metadata: serde_json::json!({}),
    };

    let session: aegis_core::Session = row.try_into().unwrap();
    assert_eq!(session.user_id(), Some(aegis_core::UserId::from_uuid(uuid(1))));
    assert!(session.guest_id().is_none());
    assert!(!session.mfa_verified);
}

#[test]
fn session_row_guest_identity() {
    let token_hash = vec![0u8; 32];
    let row = SessionRow {
        id: uuid(21),
        token_hash: token_hash.clone(),
        user_id: None,
        guest_id: Some(uuid(10)),
        expires_at: now() + time::Duration::hours(24),
        last_seen_at: now(),
        mfa_verified: false,
        user_agent: None,
        ip_address: None,
        metadata: serde_json::json!({}),
    };

    let session: aegis_core::Session = row.try_into().unwrap();
    assert!(session.user_id().is_none());
    assert_eq!(session.guest_id(), Some(aegis_core::GuestId::from_uuid(uuid(10))));
}

#[test]
fn session_row_missing_identity_fails() {
    let token_hash = vec![0u8; 32];
    let row = SessionRow {
        id: uuid(22),
        token_hash: token_hash.clone(),
        user_id: None,
        guest_id: None,
        expires_at: now(),
        last_seen_at: now(),
        mfa_verified: false,
        user_agent: None,
        ip_address: None,
        metadata: serde_json::json!({}),
    };

    let result: Result<aegis_core::Session, ConversionError> = row.try_into();
    assert!(matches!(result.unwrap_err(), ConversionError::SessionMissingIdentity));
}

#[test]
fn session_row_both_identities_fails() {
    let token_hash = vec![0u8; 32];
    let row = SessionRow {
        id: uuid(23),
        token_hash: token_hash.clone(),
        user_id: Some(uuid(1)),
        guest_id: Some(uuid(10)),
        expires_at: now(),
        last_seen_at: now(),
        mfa_verified: false,
        user_agent: None,
        ip_address: None,
        metadata: serde_json::json!({}),
    };

    let result: Result<aegis_core::Session, ConversionError> = row.try_into();
    assert!(matches!(result.unwrap_err(), ConversionError::SessionMissingIdentity));
}

#[test]
fn session_row_invalid_token_hash_length() {
    let row = SessionRow {
        id: uuid(24),
        token_hash: vec![0u8; 16],
        user_id: Some(uuid(1)),
        guest_id: None,
        expires_at: now(),
        last_seen_at: now(),
        mfa_verified: false,
        user_agent: None,
        ip_address: None,
        metadata: serde_json::json!({}),
    };

    let result: Result<aegis_core::Session, ConversionError> = row.try_into();
    assert!(matches!(
        result.unwrap_err(),
        ConversionError::InvalidTokenHashLength { expected: 32, actual: 16 }
    ));
}

#[test]
fn password_credential_row_conversion() {
    let ts = now();
    let row = PasswordCredentialRow {
        id: uuid(30),
        user_id: uuid(1),
        hash: "bcrypt$hash".to_owned(),
        algorithm_version: 1,
        created_at: ts,
        updated_at: ts,
        last_used_at: None,
    };

    let cred: aegis_core::PasswordCredential = row.into();
    assert_eq!(cred.id.as_uuid(), uuid(30));
    assert_eq!(cred.user_id.as_uuid(), uuid(1));
    assert_eq!(cred.hash, "bcrypt$hash");
    assert_eq!(cred.algorithm_version, 1);
    assert!(cred.last_used_at.is_none());
}

#[test]
fn totp_credential_row_conversion() {
    let row = TotpCredentialRow {
        id: uuid(40),
        user_id: uuid(1),
        secret_encrypted: vec![1, 2, 3],
        nonce: vec![4, 5, 6],
        algorithm: "sha256".to_owned(),
        digits: 6,
        period: 30,
        enabled: true,
        created_at: now(),
        updated_at: now(),
    };

    let cred: aegis_core::TotpCredential = row.try_into().unwrap();
    assert_eq!(cred.algorithm, TotpAlgorithm::Sha256);
    assert!(cred.enabled);
    assert_eq!(cred.digits, 6);
}

#[test]
fn totp_credential_row_invalid_algorithm() {
    let row = TotpCredentialRow {
        id: uuid(41),
        user_id: uuid(1),
        secret_encrypted: vec![],
        nonce: vec![],
        algorithm: "invalid".to_owned(),
        digits: 6,
        period: 30,
        enabled: true,
        created_at: now(),
        updated_at: now(),
    };

    let result: Result<aegis_core::TotpCredential, ConversionError> = row.try_into();
    assert!(matches!(result.unwrap_err(), ConversionError::InvalidTotpAlgorithm(_)));
}

#[test]
fn recovery_code_row_unused() {
    let row = RecoveryCodeRow {
        id: uuid(50),
        user_id: uuid(1),
        code_hash: "hash123".to_owned(),
        used_at: None,
        created_at: now(),
    };

    let code: aegis_core::RecoveryCode = row.into();
    assert!(matches!(code.state, RecoveryCodeState::Unused));
}

#[test]
fn recovery_code_row_used() {
    let ts = now();
    let row = RecoveryCodeRow {
        id: uuid(51),
        user_id: uuid(1),
        code_hash: "hash123".to_owned(),
        used_at: Some(ts),
        created_at: now(),
    };

    let code: aegis_core::RecoveryCode = row.into();
    assert!(matches!(code.state, RecoveryCodeState::Used { at } if at == ts));
}

#[test]
fn email_verification_token_row() {
    let row = EmailVerificationTokenRow {
        id: uuid(60),
        user_id: uuid(1),
        token_hash: vec![0u8; 32],
        expires_at: now() + time::Duration::hours(24),
        created_at: now(),
    };

    let token: aegis_core::PendingToken = row.try_into().unwrap();
    assert_eq!(token.purpose, PendingTokenPurpose::EmailVerification);
    assert_eq!(token.user_id.as_uuid(), uuid(1));
}

#[test]
fn password_reset_token_row() {
    let row = PasswordResetTokenRow {
        id: uuid(61),
        user_id: uuid(1),
        token_hash: vec![0u8; 32],
        expires_at: now() + time::Duration::minutes(60),
        created_at: now(),
    };

    let token: aegis_core::PendingToken = row.try_into().unwrap();
    assert_eq!(token.purpose, PendingTokenPurpose::PasswordReset);
}

#[test]
fn token_row_invalid_hash_length() {
    let row = EmailVerificationTokenRow {
        id: uuid(62),
        user_id: uuid(1),
        token_hash: vec![0u8; 16],
        expires_at: now(),
        created_at: now(),
    };

    let result: Result<aegis_core::PendingToken, ConversionError> = row.try_into();
    assert!(matches!(
        result.unwrap_err(),
        ConversionError::InvalidTokenHashLength { expected: 32, actual: 16 }
    ));
}

#[test]
fn audit_log_row_user_actor() {
    let row = AuditLogRow {
        id: 1,
        event_type: "user.login".to_owned(),
        actor_type: "user".to_owned(),
        actor_id: Some(uuid(1)),
        target_type: Some("session".to_owned()),
        target_id: Some(uuid(20)),
        ip_address: Some("127.0.0.1".to_owned()),
        user_agent: Some("test".to_owned()),
        request_id: None,
        metadata: serde_json::json!({}),
        created_at: now(),
    };

    let entry: aegis_core::AuditEntry = row.try_into().unwrap();
    assert_eq!(entry.id, 1);
    assert_eq!(entry.event_type, "user.login");
    assert!(matches!(entry.actor, Actor::User(_)));
    assert_eq!(entry.target.as_ref().unwrap().target_type, "session");
}

#[test]
fn audit_log_row_guest_actor() {
    let row = AuditLogRow {
        id: 2,
        event_type: "guest.create".to_owned(),
        actor_type: "guest".to_owned(),
        actor_id: Some(uuid(10)),
        target_type: Some("guest".to_owned()),
        target_id: Some(uuid(10)),
        ip_address: None,
        user_agent: None,
        request_id: None,
        metadata: serde_json::json!({}),
        created_at: now(),
    };

    let entry: aegis_core::AuditEntry = row.try_into().unwrap();
    assert!(matches!(entry.actor, Actor::Guest(_)));
}

#[test]
fn audit_log_row_system_actor() {
    let row = AuditLogRow {
        id: 3,
        event_type: "system.cleanup".to_owned(),
        actor_type: "system".to_owned(),
        actor_id: None,
        target_type: None,
        target_id: None,
        ip_address: None,
        user_agent: None,
        request_id: None,
        metadata: serde_json::json!({}),
        created_at: now(),
    };

    let entry: aegis_core::AuditEntry = row.try_into().unwrap();
    assert!(matches!(entry.actor, Actor::System));
    assert!(entry.target.is_none());
}

#[test]
fn audit_log_row_invalid_actor_type() {
    let row = AuditLogRow {
        id: 4,
        event_type: "test".to_owned(),
        actor_type: "unknown".to_owned(),
        actor_id: None,
        target_type: None,
        target_id: None,
        ip_address: None,
        user_agent: None,
        request_id: None,
        metadata: serde_json::json!({}),
        created_at: now(),
    };

    let result: Result<aegis_core::AuditEntry, ConversionError> = row.try_into();
    assert!(matches!(result.unwrap_err(), ConversionError::InvalidActorType(_)));
}

#[test]
fn user_role_assignment_row() {
    let ts = now();
    let row = UserRoleAssignmentRow {
        id: uuid(70),
        user_id: uuid(1),
        role_id: uuid(80),
        granted_by: Some(uuid(99)),
        granted_at: ts,
        expires_at: None,
    };

    let assignment: aegis_core::UserRoleAssignment = row.into();
    assert_eq!(assignment.user_id.as_uuid(), uuid(1));
    assert_eq!(assignment.role_id.as_uuid(), uuid(80));
    assert!(assignment.expires_at.is_none());
}
