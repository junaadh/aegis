mod common;

use aegis_app::{LoginCommand, LoginOutcome, SessionRevokeCommand, SignupCommand, TotpEnrollFinishCommand, TotpVerifyCommand};
use time::OffsetDateTime;
use totp_rs::{Algorithm, Secret, TOTP};

use crate::common::{make_app, simple_hash, test_ctx, MockClock};

fn current_totp(secret_encoded: &str, account_name: &str) -> String {
    let secret = Secret::Encoded(secret_encoded.to_owned())
        .to_bytes()
        .unwrap();
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret,
        Some("Aegis".to_owned()),
        account_name.to_owned(),
    )
    .unwrap();
    totp.generate_current().unwrap()
}

#[tokio::test]
async fn totp_enrollment_and_login_verification_flow_works() {
    let clock = MockClock::new(OffsetDateTime::now_utc());
    let (app, state) = make_app(&clock, false);
    let ctx = test_ctx();

    let signup = app
        .signup(
            SignupCommand {
                email: "mfa@example.com".to_owned(),
                password: "CorrectHorseBatteryStaple1!".to_owned(),
                display_name: "Mfa User".to_owned(),
            },
            &ctx,
        )
        .await
        .unwrap();

    let enroll = app.enroll_totp_start(signup.user.id).await.unwrap();
    assert!(!enroll.secret.is_empty());
    assert!(enroll.qr_code_url.starts_with("otpauth://"));

    let finish_code = current_totp(&enroll.secret, signup.user.email.as_str());
    let recovery_codes = app
        .enroll_totp_finish(
            signup.user.id,
            TotpEnrollFinishCommand { code: finish_code },
            &ctx,
        )
        .await
        .unwrap();
    assert_eq!(recovery_codes.len(), 8);

    let login = app
        .login_with_password(
            LoginCommand {
                email: signup.user.email.as_str().to_owned(),
                password: "CorrectHorseBatteryStaple1!".to_owned(),
            },
            &ctx,
        )
        .await
        .unwrap();

    let session_token = match login {
        LoginOutcome::RequiresMfa { session_token, .. } => session_token,
        LoginOutcome::Authenticated(_) => panic!("expected mfa requirement"),
    };

    let verify_code = current_totp(&enroll.secret, signup.user.email.as_str());
    app.verify_totp(
        signup.user.id,
        simple_hash(&session_token),
        TotpVerifyCommand { code: verify_code },
        &ctx,
    )
    .await
    .unwrap();

    let validate = app
        .validate_session(aegis_app::ValidateSessionCommand {
            token_hash: simple_hash(&session_token),
        })
        .await
        .unwrap();
    assert!(validate.valid);
    assert!(validate.mfa_verified);

    let stored_sessions = state.read().await.sessions.clone();
    let stored = stored_sessions
        .get(&simple_hash(&session_token))
        .expect("session must exist");
    assert!(stored.mfa_verified);
}

#[tokio::test]
async fn revoke_session_and_revoke_all_sessions_work() {
    let clock = MockClock::new(OffsetDateTime::now_utc());
    let (app, state) = make_app(&clock, false);
    let ctx = test_ctx();

    let signup = app
        .signup(
            SignupCommand {
                email: "session@example.com".to_owned(),
                password: "CorrectHorseBatteryStaple1!".to_owned(),
                display_name: "Session User".to_owned(),
            },
            &ctx,
        )
        .await
        .unwrap();

    let login_one = app
        .login_with_password(
            LoginCommand {
                email: signup.user.email.as_str().to_owned(),
                password: "CorrectHorseBatteryStaple1!".to_owned(),
            },
            &ctx,
        )
        .await
        .unwrap();
    let login_two = app
        .login_with_password(
            LoginCommand {
                email: signup.user.email.as_str().to_owned(),
                password: "CorrectHorseBatteryStaple1!".to_owned(),
            },
            &ctx,
        )
        .await
        .unwrap();

    let token_one = match login_one {
        LoginOutcome::Authenticated(auth) => auth.session_token,
        LoginOutcome::RequiresMfa { .. } => panic!("unexpected mfa requirement"),
    };
    let token_two = match login_two {
        LoginOutcome::Authenticated(auth) => auth.session_token,
        LoginOutcome::RequiresMfa { .. } => panic!("unexpected mfa requirement"),
    };

    let session_id_two = state
        .read()
        .await
        .sessions
        .get(&simple_hash(&token_two))
        .unwrap()
        .id
        .as_uuid();

    app.revoke_session(
        signup.user.id,
        SessionRevokeCommand {
            session_id: Some(session_id_two),
        },
        &ctx,
    )
    .await
    .unwrap();
    assert!(!state.read().await.sessions.contains_key(&simple_hash(&token_two)));

    app.revoke_all_sessions(signup.user.id, Some(simple_hash(&token_one)), &ctx)
        .await
        .unwrap();

    let sessions = state.read().await.sessions.clone();
    assert!(sessions.contains_key(&simple_hash(&token_one)));
    assert_eq!(sessions.len(), 1);
}
