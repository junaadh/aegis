mod common;

use time::OffsetDateTime;

use aegis_app::{
    AppError, LoginCommand, LoginOutcome, LogoutCommand, SignupCommand,
    UpdateProfileCommand,
};
use aegis_core::{Actor, SessionIdentity, UserStatus};

use common::*;

async fn signup_user_local(
    app: &TestApp,
    email: &str,
    password: &str,
) -> aegis_app::AuthResult {
    app.signup(
        SignupCommand {
            email: email.to_owned(),
            password: password.to_owned(),
            display_name: "Test User".to_owned(),
        },
        &test_ctx(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn signup_creates_active_user_when_email_disabled() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, state) = make_app(&clock, false);

    let auth = app
        .signup(
            SignupCommand {
                email: "new@test.com".to_owned(),
                password: "password123".to_owned(),
                display_name: "New User".to_owned(),
            },
            &test_ctx(),
        )
        .await
        .unwrap();

    assert_eq!(auth.user.status, UserStatus::Active);
    assert!(auth.session_token.starts_with("tok-"));
    assert!(auth.mfa_verified);

    let s = state.read().await;
    assert_eq!(s.users.len(), 1);
    assert_eq!(s.credentials_password.len(), 1);
    assert_eq!(s.sessions.len(), 1);
    assert!(s.pending_tokens.is_empty());
    assert!(s.outbox.is_empty());

    let audit = &s.audits[0];
    assert_eq!(audit.event_type, "user.signup");
    assert!(matches!(audit.actor, Actor::User(_)));
    assert_eq!(audit.target.as_ref().unwrap().target_type, "user");
}

#[tokio::test]
async fn signup_creates_pending_user_when_email_enabled() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, state) = make_app(&clock, true);

    let auth = app
        .signup(
            SignupCommand {
                email: "verify@test.com".to_owned(),
                password: "password123".to_owned(),
                display_name: "Verify User".to_owned(),
            },
            &test_ctx(),
        )
        .await
        .unwrap();

    assert_eq!(auth.user.status, UserStatus::PendingVerification);
    assert!(!auth.user.is_email_verified());
    assert!(auth.mfa_verified);

    let s = state.read().await;
    assert_eq!(s.pending_tokens.len(), 1);
    assert_eq!(s.outbox.len(), 1);
    match &s.outbox[0] {
        aegis_app::JobPayload::SendVerificationEmail { email, .. } => {
            assert_eq!(email, "verify@test.com");
        }
        _ => panic!("expected SendVerificationEmail job"),
    }
}

#[tokio::test]
async fn signup_rejects_duplicate_email() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, _state) = make_app(&clock, false);

    app.signup(
        SignupCommand {
            email: "dup@test.com".to_owned(),
            password: "password123".to_owned(),
            display_name: "First".to_owned(),
        },
        &test_ctx(),
    )
    .await
    .unwrap();

    let result = app
        .signup(
            SignupCommand {
                email: "dup@test.com".to_owned(),
                password: "password456".to_owned(),
                display_name: "Second".to_owned(),
            },
            &test_ctx(),
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::EmailAlreadyExists));
}

#[tokio::test]
async fn signup_rejects_weak_password() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, _state) = make_app(&clock, false);

    let result = app
        .signup(
            SignupCommand {
                email: "weak@test.com".to_owned(),
                password: "short".to_owned(),
                display_name: "Weak".to_owned(),
            },
            &test_ctx(),
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::PasswordTooWeak(_)));
}

#[tokio::test]
async fn signup_rejects_invalid_email() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, _state) = make_app(&clock, false);

    let result = app
        .signup(
            SignupCommand {
                email: "no-at-sign".to_owned(),
                password: "password123".to_owned(),
                display_name: "Bad Email".to_owned(),
            },
            &test_ctx(),
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::Validation(_)));
}

#[tokio::test]
async fn signup_normalizes_email_to_lowercase() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, state) = make_app(&clock, false);

    let auth = app
        .signup(
            SignupCommand {
                email: "Upper@Case.COM".to_owned(),
                password: "password123".to_owned(),
                display_name: "Test".to_owned(),
            },
            &test_ctx(),
        )
        .await
        .unwrap();

    assert_eq!(auth.user.email.as_str(), "upper@case.com");

    let s = state.read().await;
    let stored = s.users.values().next().unwrap();
    assert_eq!(stored.email.as_str(), "upper@case.com");
}

#[tokio::test]
async fn login_succeeds_with_correct_password() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, _state) = make_app(&clock, false);

    app.signup(
        SignupCommand {
            email: "login@test.com".to_owned(),
            password: "password123".to_owned(),
            display_name: "Login User".to_owned(),
        },
        &test_ctx(),
    )
    .await
    .unwrap();

    let outcome = app
        .login_with_password(
            LoginCommand {
                email: "login@test.com".to_owned(),
                password: "password123".to_owned(),
            },
            &test_ctx(),
        )
        .await
        .unwrap();

    match outcome {
        LoginOutcome::Authenticated(auth) => {
            assert!(auth.session_token.starts_with("tok-"));
            assert_eq!(auth.user.email.as_str(), "login@test.com");
        }
        LoginOutcome::RequiresMfa { .. } => {
            panic!("expected authenticated, got mfa required")
        }
    }
}

#[tokio::test]
async fn login_fails_with_wrong_password() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, _state) = make_app(&clock, false);

    app.signup(
        SignupCommand {
            email: "wrong@test.com".to_owned(),
            password: "password123".to_owned(),
            display_name: "Wrong Pw".to_owned(),
        },
        &test_ctx(),
    )
    .await
    .unwrap();

    let result = app
        .login_with_password(
            LoginCommand {
                email: "wrong@test.com".to_owned(),
                password: "wrongpassword".to_owned(),
            },
            &test_ctx(),
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::InvalidCredentials));
}

#[tokio::test]
async fn login_fails_for_nonexistent_user() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, _state) = make_app(&clock, false);

    let result = app
        .login_with_password(
            LoginCommand {
                email: "nobody@test.com".to_owned(),
                password: "password123".to_owned(),
            },
            &test_ctx(),
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::InvalidCredentials));
}

#[tokio::test]
async fn login_fails_for_deleted_user() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, state) = make_app(&clock, false);

    app.signup(
        SignupCommand {
            email: "deleted@test.com".to_owned(),
            password: "password123".to_owned(),
            display_name: "Deleted".to_owned(),
        },
        &test_ctx(),
    )
    .await
    .unwrap();

    {
        let mut s = state.write().await;
        let user = s.users.values_mut().next().unwrap();
        user.delete_at(now);
    }

    let result = app
        .login_with_password(
            LoginCommand {
                email: "deleted@test.com".to_owned(),
                password: "password123".to_owned(),
            },
            &test_ctx(),
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::Unauthorized));
}

#[tokio::test]
async fn login_fails_for_disabled_user() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, state) = make_app(&clock, false);

    app.signup(
        SignupCommand {
            email: "disabled@test.com".to_owned(),
            password: "password123".to_owned(),
            display_name: "Disabled".to_owned(),
        },
        &test_ctx(),
    )
    .await
    .unwrap();

    {
        let mut s = state.write().await;
        let user = s.users.values_mut().next().unwrap();
        user.disable_at(now).unwrap();
    }

    let result = app
        .login_with_password(
            LoginCommand {
                email: "disabled@test.com".to_owned(),
                password: "password123".to_owned(),
            },
            &test_ctx(),
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::Unauthorized));
}

#[tokio::test]
async fn login_fails_for_unverified_when_email_enforced() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, _state) = make_app(&clock, true);

    app.signup(
        SignupCommand {
            email: "unverified@test.com".to_owned(),
            password: "password123".to_owned(),
            display_name: "Unverified".to_owned(),
        },
        &test_ctx(),
    )
    .await
    .unwrap();

    let result = app
        .login_with_password(
            LoginCommand {
                email: "unverified@test.com".to_owned(),
                password: "password123".to_owned(),
            },
            &test_ctx(),
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::EmailNotVerified));
}

#[tokio::test]
async fn login_succeeds_for_unverified_when_email_disabled() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, _state) = make_app(&clock, false);

    app.signup(
        SignupCommand {
            email: "noemail@test.com".to_owned(),
            password: "password123".to_owned(),
            display_name: "No Email".to_owned(),
        },
        &test_ctx(),
    )
    .await
    .unwrap();

    let result = app
        .login_with_password(
            LoginCommand {
                email: "noemail@test.com".to_owned(),
                password: "password123".to_owned(),
            },
            &test_ctx(),
        )
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn login_creates_session_with_correct_identity() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, state) = make_app(&clock, false);

    let auth = app
        .signup(
            SignupCommand {
                email: "session@test.com".to_owned(),
                password: "password123".to_owned(),
                display_name: "Session".to_owned(),
            },
            &test_ctx(),
        )
        .await
        .unwrap();
    let user_id = auth.user.id;

    let _outcome = app
        .login_with_password(
            LoginCommand {
                email: "session@test.com".to_owned(),
                password: "password123".to_owned(),
            },
            &test_ctx(),
        )
        .await
        .unwrap();

    let s = state.read().await;
    let login_sessions: Vec<_> = s.sessions.values()
        .filter(|s| matches!(s.identity, SessionIdentity::User(uid) if uid == user_id))
        .collect();
    assert!(login_sessions.len() >= 2);
}

#[tokio::test]
async fn login_requires_mfa_when_totp_enabled() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, state) = make_app(&clock, false);

    let auth = app
        .signup(
            SignupCommand {
                email: "mfa@test.com".to_owned(),
                password: "password123".to_owned(),
                display_name: "Mfa User".to_owned(),
            },
            &test_ctx(),
        )
        .await
        .unwrap();

    {
        let mut s = state.write().await;
        s.credentials_totp.insert(
            auth.user.id.as_uuid(),
            aegis_core::TotpCredential {
                id: aegis_core::TotpCredentialId::new(),
                user_id: auth.user.id,
                secret_encrypted: vec![1, 2, 3],
                nonce: vec![4, 5, 6],
                algorithm: aegis_core::TotpAlgorithm::Sha1,
                digits: 6,
                period: 30,
                enabled: true,
                created_at: now,
                updated_at: now,
            },
        );
    }

    let outcome = app
        .login_with_password(
            LoginCommand {
                email: "mfa@test.com".to_owned(),
                password: "password123".to_owned(),
            },
            &test_ctx(),
        )
        .await
        .unwrap();

    match outcome {
        LoginOutcome::RequiresMfa { session_token, .. } => {
            assert!(session_token.starts_with("tok-"));
        }
        LoginOutcome::Authenticated(_) => panic!("expected mfa requirement"),
    }

    let s = state.read().await;
    let mfa_audit = s
        .audits
        .iter()
        .find(|a| a.event_type == "user.login.mfa_required")
        .unwrap();
    assert!(matches!(mfa_audit.actor, Actor::User(_)));
}

#[tokio::test]
async fn login_rehashes_password_when_algorithm_is_stale() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, state) = make_app(&clock, false);

    let auth = app
        .signup(
            SignupCommand {
                email: "rehash@test.com".to_owned(),
                password: "password123".to_owned(),
                display_name: "Rehash User".to_owned(),
            },
            &test_ctx(),
        )
        .await
        .unwrap();

    {
        let mut s = state.write().await;
        let cred = s
            .credentials_password
            .get_mut(&auth.user.id.as_uuid())
            .unwrap();
        cred.algorithm_version = 0;
    }

    let outcome = app
        .login_with_password(
            LoginCommand {
                email: "rehash@test.com".to_owned(),
                password: "password123".to_owned(),
            },
            &test_ctx(),
        )
        .await
        .unwrap();

    assert!(matches!(outcome, LoginOutcome::Authenticated(_)));

    let s = state.read().await;
    let cred = s.credentials_password.get(&auth.user.id.as_uuid()).unwrap();
    assert_eq!(cred.algorithm_version, 1);
    assert_eq!(cred.hash, "hashed:password123");
}

#[tokio::test]
async fn login_audit_trail() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, state) = make_app(&clock, false);

    app.signup(
        SignupCommand {
            email: "audit@test.com".to_owned(),
            password: "password123".to_owned(),
            display_name: "Audit".to_owned(),
        },
        &test_ctx(),
    )
    .await
    .unwrap();

    app.login_with_password(
        LoginCommand {
            email: "audit@test.com".to_owned(),
            password: "password123".to_owned(),
        },
        &test_ctx(),
    )
    .await
    .unwrap();

    let s = state.read().await;
    let login_audit = s
        .audits
        .iter()
        .find(|a| a.event_type == "user.login")
        .unwrap();
    assert!(matches!(login_audit.actor, Actor::User(_)));
    assert_eq!(login_audit.target.as_ref().unwrap().target_type, "session");
}

#[tokio::test]
async fn logout_deletes_session() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, state) = make_app(&clock, false);

    let auth = app
        .signup(
            SignupCommand {
                email: "logout@test.com".to_owned(),
                password: "password123".to_owned(),
                display_name: "Logout".to_owned(),
            },
            &test_ctx(),
        )
        .await
        .unwrap();

    let token_hash = common::simple_hash(&auth.session_token);

    assert!(state.read().await.sessions.len() == 1);

    app.logout(
        LogoutCommand {
            session_token_hash: token_hash,
        },
        &test_ctx(),
    )
    .await
    .unwrap();

    assert!(state.read().await.sessions.is_empty());

    let s = state.read().await;
    let logout_audit = s
        .audits
        .iter()
        .find(|a| a.event_type == "session.logout")
        .unwrap();
    assert!(matches!(logout_audit.actor, Actor::User(_)));
}

#[tokio::test]
async fn logout_idempotent_for_missing_session() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, _state) = make_app(&clock, false);

    let fake_hash = [0u8; 32];
    let result = app
        .logout(
            LogoutCommand {
                session_token_hash: fake_hash,
            },
            &test_ctx(),
        )
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn logout_for_guest_session() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, state) = make_app(&clock, false);

    let guest_result = app
        .create_guest(aegis_app::CreateGuestCommand, &test_ctx())
        .await
        .unwrap();
    let token_hash = common::simple_hash(&guest_result.session_token);

    app.logout(
        LogoutCommand {
            session_token_hash: token_hash,
        },
        &test_ctx(),
    )
    .await
    .unwrap();

    assert!(state.read().await.sessions.is_empty());

    let s = state.read().await;
    let logout_audit = s
        .audits
        .iter()
        .find(|a| a.event_type == "session.logout")
        .unwrap();
    assert!(matches!(logout_audit.actor, Actor::Guest(_)));
}

#[tokio::test]
async fn get_current_identity_returns_user() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, _state) = make_app(&clock, false);

    let auth = signup_user_local(&app, "me@test.com", "password123").await;
    let user_id = auth.user.id;

    let identity = app.get_current_identity(user_id).await.unwrap();

    assert!(identity.user.is_some());
    assert!(identity.guest.is_none());
    assert_eq!(identity.user.unwrap().email.as_str(), "me@test.com");
    assert_eq!(identity.credentials.len(), 1);
    assert_eq!(
        identity.credentials[0].kind,
        aegis_core::CredentialKind::Password
    );
}

#[tokio::test]
async fn get_current_identity_not_found() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, _state) = make_app(&clock, false);

    let result = app.get_current_identity(aegis_core::UserId::new()).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::NotFound(_)));
}

#[tokio::test]
async fn update_profile_changes_display_name() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, _state) = make_app(&clock, false);

    let auth = signup_user_local(&app, "update@test.com", "password123").await;
    let user_id = auth.user.id;

    let result = app
        .update_profile(
            user_id,
            UpdateProfileCommand {
                display_name: Some("Updated Name".to_owned()),
            },
            &test_ctx(),
        )
        .await
        .unwrap();

    assert_eq!(result.user.unwrap().display_name.as_str(), "Updated Name");
}

#[tokio::test]
async fn update_profile_no_change_returns_current() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, _state) = make_app(&clock, false);

    let auth =
        signup_user_local(&app, "nochange@test.com", "password123").await;
    let user_id = auth.user.id;

    let result = app
        .update_profile(
            user_id,
            UpdateProfileCommand { display_name: None },
            &test_ctx(),
        )
        .await
        .unwrap();

    assert_eq!(result.user.unwrap().display_name.as_str(), "Test User");
}
