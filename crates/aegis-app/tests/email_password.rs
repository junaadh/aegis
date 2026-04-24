mod common;

use time::{Duration, OffsetDateTime};

use aegis_app::TokenGenerator;
use aegis_app::{
    AppError, ChangePasswordCommand, ForgotPasswordCommand,
    ResendVerificationCommand, ResetPasswordCommand, VerifyEmailCommand,
};
use aegis_core::UserStatus;

use common::*;

async fn signup_user_local(
    app: &TestApp,
    email: &str,
    password: &str,
) -> aegis_app::AuthResult {
    app.signup(
        aegis_app::SignupCommand {
            email: email.to_owned(),
            password: password.to_owned(),
            display_name: "Test User".to_owned(),
        },
        &test_ctx(),
    )
    .await
    .unwrap()
}

async fn create_session_for_user_local(
    state: &std::sync::Arc<tokio::sync::RwLock<MockState>>,
    user_id: aegis_core::UserId,
) -> String {
    let (token, hash) = MockTokenGen.generate_opaque(32).await.unwrap();
    let now = OffsetDateTime::now_utc();
    let session = aegis_core::Session::builder(
        aegis_core::SessionId::new(),
        hash,
        aegis_core::SessionIdentity::User(user_id),
        now + Duration::hours(24),
    )
    .build();
    state.write().await.sessions.insert(hash, session);
    token
}

fn extract_verification_token(
    state: &std::sync::Arc<tokio::sync::RwLock<MockState>>,
) -> Option<String> {
    let s = state.try_read().unwrap();
    s.outbox.iter().find_map(|j| match j {
        aegis_app::JobPayload::SendVerificationEmail { token, .. } => {
            Some(token.clone())
        }
        _ => None,
    })
}

fn extract_reset_token(
    state: &std::sync::Arc<tokio::sync::RwLock<MockState>>,
) -> Option<String> {
    let s = state.try_read().unwrap();
    s.outbox.iter().find_map(|j| match j {
        aegis_app::JobPayload::SendPasswordResetEmail { token, .. } => {
            Some(token.clone())
        }
        _ => None,
    })
}

#[tokio::test]
async fn verify_email_activates_account() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, state) = make_app(&clock, true);

    let auth = signup_user_local(&app, "verify@test.com", "password123");
    let auth = auth.await;

    assert_eq!(auth.user.status, UserStatus::PendingVerification);
    assert!(!auth.user.is_email_verified());

    let token = extract_verification_token(&state).unwrap();

    app.verify_email(VerifyEmailCommand { token })
        .await
        .unwrap();

    let s = state.read().await;
    let user = s.users.get(&auth.user.id.as_uuid()).unwrap();
    assert_eq!(user.status, UserStatus::Active);
    assert!(user.is_email_verified());

    let verify_audit = s
        .audits
        .iter()
        .find(|a| a.event_type == "user.verify_email")
        .unwrap();
    assert!(matches!(verify_audit.actor, aegis_core::Actor::User(_)));
}

#[tokio::test]
async fn verify_email_consumes_token() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, state) = make_app(&clock, true);

    signup_user_local(&app, "consume@test.com", "password123").await;
    let token = extract_verification_token(&state).unwrap();

    app.verify_email(VerifyEmailCommand {
        token: token.clone(),
    })
    .await
    .unwrap();

    let result = app.verify_email(VerifyEmailCommand { token }).await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::TokenInvalid));
}

#[tokio::test]
async fn expired_verification_token_fails() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, state) = make_app(&clock, true);

    signup_user_local(&app, "expired@test.com", "password123").await;
    let token = extract_verification_token(&state).unwrap();

    let future = now + Duration::hours(25);
    *clock.handle().write().await = future;

    let result = app.verify_email(VerifyEmailCommand { token }).await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::TokenInvalid));
}

#[tokio::test]
async fn wrong_purpose_token_fails_for_verification() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, state) = make_app(&clock, true);

    signup_user_local(&app, "wrong@test.com", "password123").await;

    app.forgot_password(ForgotPasswordCommand {
        email: "wrong@test.com".to_owned(),
    })
    .await
    .unwrap();

    let reset_token = extract_reset_token(&state).unwrap();

    let result = app
        .verify_email(VerifyEmailCommand { token: reset_token })
        .await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::TokenInvalid));
}

#[tokio::test]
async fn resend_verification_creates_new_token() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, state) = make_app(&clock, true);

    signup_user_local(&app, "resend@test.com", "password123").await;

    let first_count = state.read().await.outbox.len();

    app.resend_verification(ResendVerificationCommand {
        email: "resend@test.com".to_owned(),
    })
    .await
    .unwrap();

    let s = state.read().await;
    assert_eq!(s.outbox.len(), first_count + 1);

    let resend_audit = s
        .audits
        .iter()
        .find(|a| a.event_type == "user.resend_verification")
        .unwrap();
    assert!(matches!(resend_audit.actor, aegis_core::Actor::User(_)));
}

#[tokio::test]
async fn resend_verification_silently_succeeds_for_already_verified() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, state) = make_app(&clock, true);

    signup_user_local(&app, "already@test.com", "password123").await;
    let token = extract_verification_token(&state).unwrap();

    app.verify_email(VerifyEmailCommand { token })
        .await
        .unwrap();

    let outbox_before = state.read().await.outbox.len();

    app.resend_verification(ResendVerificationCommand {
        email: "already@test.com".to_owned(),
    })
    .await
    .unwrap();

    assert_eq!(state.read().await.outbox.len(), outbox_before);
}

#[tokio::test]
async fn resend_verification_fails_for_unknown_email() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, _) = make_app(&clock, true);

    let result = app
        .resend_verification(ResendVerificationCommand {
            email: "nonexistent@test.com".to_owned(),
        })
        .await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::NotFound(_)));
}

#[tokio::test]
async fn forgot_password_does_not_leak_account_existence() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, _state) = make_app(&clock, true);

    let result_nonexistent = app
        .forgot_password(ForgotPasswordCommand {
            email: "nobody@test.com".to_owned(),
        })
        .await;
    assert!(result_nonexistent.is_ok());

    signup_user_local(&app, "exists@test.com", "password123").await;

    let result_exists = app
        .forgot_password(ForgotPasswordCommand {
            email: "exists@test.com".to_owned(),
        })
        .await;
    assert!(result_exists.is_ok());
}

#[tokio::test]
async fn forgot_password_enqueues_email_for_active_user() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, state) = make_app(&clock, true);

    signup_user_local(&app, "reset@test.com", "password123").await;
    let token = extract_verification_token(&state).unwrap();
    app.verify_email(VerifyEmailCommand { token })
        .await
        .unwrap();

    app.forgot_password(ForgotPasswordCommand {
        email: "reset@test.com".to_owned(),
    })
    .await
    .unwrap();

    let reset_token = extract_reset_token(&state);
    assert!(reset_token.is_some());

    let s = state.read().await;
    let forgot_audit = s
        .audits
        .iter()
        .find(|a| a.event_type == "user.forgot_password")
        .unwrap();
    assert!(matches!(forgot_audit.actor, aegis_core::Actor::User(_)));
}

#[tokio::test]
async fn reset_password_updates_credential() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, state) = make_app(&clock, true);

    signup_user_local(&app, "resetpw@test.com", "password123").await;
    let verify_token = extract_verification_token(&state).unwrap();
    app.verify_email(VerifyEmailCommand {
        token: verify_token,
    })
    .await
    .unwrap();

    app.forgot_password(ForgotPasswordCommand {
        email: "resetpw@test.com".to_owned(),
    })
    .await
    .unwrap();

    let reset_token = extract_reset_token(&state).unwrap();

    app.reset_password(ResetPasswordCommand {
        token: reset_token,
        new_password: "newpassword456".to_owned(),
    })
    .await
    .unwrap();

    let s = state.read().await;
    let user = s
        .users
        .values()
        .find(|u| u.email.as_str() == "resetpw@test.com")
        .unwrap();
    let cred = s.credentials_password.get(&user.id.as_uuid()).unwrap();
    assert_eq!(cred.hash, "hashed:newpassword456");

    let reset_audit = s
        .audits
        .iter()
        .find(|a| a.event_type == "user.reset_password")
        .unwrap();
    assert!(matches!(reset_audit.actor, aegis_core::Actor::User(_)));
}

#[tokio::test]
async fn reset_password_revokes_all_sessions() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, state) = make_app(&clock, true);

    let auth = signup_user_local(&app, "revoke@test.com", "password123").await;
    let verify_token = extract_verification_token(&state).unwrap();
    app.verify_email(VerifyEmailCommand {
        token: verify_token,
    })
    .await
    .unwrap();

    create_session_for_user_local(&state, auth.user.id).await;

    assert!(state.read().await.sessions.len() >= 2);

    app.forgot_password(ForgotPasswordCommand {
        email: "revoke@test.com".to_owned(),
    })
    .await
    .unwrap();

    let reset_token = extract_reset_token(&state).unwrap();

    app.reset_password(ResetPasswordCommand {
        token: reset_token,
        new_password: "brandnew789".to_owned(),
    })
    .await
    .unwrap();

    assert!(state.read().await.sessions.is_empty());
}

#[tokio::test]
async fn reset_password_consumes_token() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, state) = make_app(&clock, true);

    signup_user_local(&app, "reuse@test.com", "password123").await;
    let verify_token = extract_verification_token(&state).unwrap();
    app.verify_email(VerifyEmailCommand {
        token: verify_token,
    })
    .await
    .unwrap();

    app.forgot_password(ForgotPasswordCommand {
        email: "reuse@test.com".to_owned(),
    })
    .await
    .unwrap();

    let reset_token = extract_reset_token(&state).unwrap();

    app.reset_password(ResetPasswordCommand {
        token: reset_token.clone(),
        new_password: "firstreset1".to_owned(),
    })
    .await
    .unwrap();

    let result = app
        .reset_password(ResetPasswordCommand {
            token: reset_token,
            new_password: "secondreset2".to_owned(),
        })
        .await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::TokenInvalid));
}

#[tokio::test]
async fn expired_reset_token_fails() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, state) = make_app(&clock, true);

    signup_user_local(&app, "expiredreset@test.com", "password123").await;
    let verify_token = extract_verification_token(&state).unwrap();
    app.verify_email(VerifyEmailCommand {
        token: verify_token,
    })
    .await
    .unwrap();

    app.forgot_password(ForgotPasswordCommand {
        email: "expiredreset@test.com".to_owned(),
    })
    .await
    .unwrap();

    let reset_token = extract_reset_token(&state).unwrap();

    let future = now + Duration::minutes(61);
    *clock.handle().write().await = future;

    let result = app
        .reset_password(ResetPasswordCommand {
            token: reset_token,
            new_password: "newpassword1".to_owned(),
        })
        .await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::TokenInvalid));
}

#[tokio::test]
async fn wrong_purpose_token_fails_for_reset() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, state) = make_app(&clock, true);

    signup_user_local(&app, "wrongreset@test.com", "password123").await;
    let verify_token = extract_verification_token(&state).unwrap();

    let result = app
        .reset_password(ResetPasswordCommand {
            token: verify_token,
            new_password: "newpassword1".to_owned(),
        })
        .await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::TokenInvalid));
}

#[tokio::test]
async fn change_password_succeeds() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, state) = make_app(&clock, false);

    let auth = signup_user_local(&app, "change@test.com", "oldpassword1").await;
    let user_id = auth.user.id;

    app.change_password(
        user_id,
        ChangePasswordCommand {
            current_password: "oldpassword1".to_owned(),
            new_password: "newpassword2".to_owned(),
        },
        &test_ctx(),
    )
    .await
    .unwrap();

    let s = state.read().await;
    let cred = s.credentials_password.get(&user_id.as_uuid()).unwrap();
    assert_eq!(cred.hash, "hashed:newpassword2");

    let audit = s
        .audits
        .iter()
        .find(|a| a.event_type == "user.change_password")
        .unwrap();
    assert!(matches!(audit.actor, aegis_core::Actor::User(_)));
}

#[tokio::test]
async fn change_password_wrong_current_fails() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, _state) = make_app(&clock, false);

    let auth =
        signup_user_local(&app, "wrongchange@test.com", "correctpass1").await;

    let result = app
        .change_password(
            auth.user.id,
            ChangePasswordCommand {
                current_password: "wrongpass1".to_owned(),
                new_password: "newpass12345".to_owned(),
            },
            &test_ctx(),
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::InvalidCredentials));
}

#[tokio::test]
async fn change_password_revokes_sessions() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, state) = make_app(&clock, false);

    let auth =
        signup_user_local(&app, "revchange@test.com", "oldpassword1").await;

    create_session_for_user_local(&state, auth.user.id).await;
    assert!(state.read().await.sessions.len() >= 2);

    app.change_password(
        auth.user.id,
        ChangePasswordCommand {
            current_password: "oldpassword1".to_owned(),
            new_password: "newpassword2".to_owned(),
        },
        &test_ctx(),
    )
    .await
    .unwrap();

    assert!(state.read().await.sessions.is_empty());
}

#[tokio::test]
async fn verify_email_idempotent_for_already_verified() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, state) = make_app(&clock, true);

    signup_user_local(&app, "idempotent@test.com", "password123").await;
    let token = extract_verification_token(&state).unwrap();

    app.verify_email(VerifyEmailCommand {
        token: token.clone(),
    })
    .await
    .unwrap();

    assert!(state.read().await.pending_tokens.is_empty());
}
