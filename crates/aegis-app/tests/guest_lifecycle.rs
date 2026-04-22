mod common;

use time::{Duration, OffsetDateTime};

use aegis_core::{Actor, GuestStatus};
use aegis_app::{
    AppError, CreateGuestCommand, GuestConvertCommand, GuestEmailCommand,
    SignupCommand,
};

use common::*;

#[tokio::test]
async fn create_guest_succeeds() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, state) = make_app(&clock, false);

    let result = app.create_guest(CreateGuestCommand, &test_ctx()).await.unwrap();

    assert!(result.session_token.starts_with("tok-"));
    assert_eq!(result.guest.status, GuestStatus::Active);
    assert!(result.guest.email.is_none());
    assert!(result.guest.converted_to.is_none());

    let s = state.read().await;
    assert_eq!(s.guests.len(), 1);
    assert_eq!(s.sessions.len(), 1);
    assert_eq!(s.audits.len(), 1);
    assert_eq!(s.audits[0].event_type, "guest.create");
    assert!(matches!(s.audits[0].actor, Actor::Guest(_)));
}

#[tokio::test]
async fn create_guest_has_correct_ttl() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, _) = make_app(&clock, false);

    let result = app.create_guest(CreateGuestCommand, &test_ctx()).await.unwrap();

    let expected_expiry = now + Duration::days(30);
    assert_eq!(result.guest.expires_at, expected_expiry);
}

#[tokio::test]
async fn associate_guest_email_succeeds() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, state) = make_app(&clock, false);

    let guest_result = app.create_guest(CreateGuestCommand, &test_ctx()).await.unwrap();
    let guest_id = guest_result.guest.id;

    app.associate_guest_email(
        guest_id,
        GuestEmailCommand { email: "test@example.com".to_owned() },
        &test_ctx(),
    )
    .await
    .unwrap();

    let s = state.read().await;
    let guest = s.guests.get(&guest_id.as_uuid()).unwrap();
    assert_eq!(guest.email.as_ref().unwrap().as_str(), "test@example.com");

    let email_audit = s.audits.iter().find(|a| a.event_type == "guest.associate_email").unwrap();
    assert!(matches!(email_audit.actor, Actor::Guest(_)));
}

#[tokio::test]
async fn attach_email_after_conversion_fails() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, _) = make_app(&clock, false);

    let guest_result = app.create_guest(CreateGuestCommand, &test_ctx()).await.unwrap();
    let guest_id = guest_result.guest.id;

    app.associate_guest_email(
        guest_id,
        GuestEmailCommand { email: "before@convert.com".to_owned() },
        &test_ctx(),
    )
    .await
    .unwrap();

    app.convert_guest(
        guest_id,
        GuestConvertCommand {
            email: Some("converted@example.com".to_owned()),
            password: "password123".to_owned(),
            display_name: Some("Converted User".to_owned()),
        },
        &test_ctx(),
    )
    .await
    .unwrap();

    let result = app
        .associate_guest_email(
            guest_id,
            GuestEmailCommand { email: "after@convert.com".to_owned() },
            &test_ctx(),
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::GuestAlreadyConverted));
}

#[tokio::test]
async fn convert_guest_twice_fails() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, _) = make_app(&clock, false);

    let guest_result = app.create_guest(CreateGuestCommand, &test_ctx()).await.unwrap();
    let guest_id = guest_result.guest.id;

    app.convert_guest(
        guest_id,
        GuestConvertCommand {
            email: Some("user@example.com".to_owned()),
            password: "password123".to_owned(),
            display_name: Some("Test User".to_owned()),
        },
        &test_ctx(),
    )
    .await
    .unwrap();

    let result = app
        .convert_guest(
            guest_id,
            GuestConvertCommand {
                email: Some("second@example.com".to_owned()),
                password: "password456".to_owned(),
                display_name: Some("Second User".to_owned()),
            },
            &test_ctx(),
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::GuestAlreadyConverted));
}

#[tokio::test]
async fn expired_guest_cannot_associate_email() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, state) = make_app(&clock, false);

    let guest_result = app.create_guest(CreateGuestCommand, &test_ctx()).await.unwrap();
    let guest_id = guest_result.guest.id;

    let expired = now + Duration::days(31);
    {
        let mut s = state.write().await;
        let guest = s.guests.get_mut(&guest_id.as_uuid()).unwrap();
        guest.expires_at = expired - Duration::seconds(1);
    }
    *clock.handle().write().await = expired;

    let result = app
        .associate_guest_email(
            guest_id,
            GuestEmailCommand { email: "expired@example.com".to_owned() },
            &test_ctx(),
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::GuestExpired));
}

#[tokio::test]
async fn expired_guest_cannot_convert() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, state) = make_app(&clock, false);

    let guest_result = app.create_guest(CreateGuestCommand, &test_ctx()).await.unwrap();
    let guest_id = guest_result.guest.id;

    let expired = now + Duration::days(31);
    {
        let mut s = state.write().await;
        let guest = s.guests.get_mut(&guest_id.as_uuid()).unwrap();
        guest.expires_at = expired - Duration::seconds(1);
    }
    *clock.handle().write().await = expired;

    let result = app
        .convert_guest(
            guest_id,
            GuestConvertCommand {
                email: Some("expired@example.com".to_owned()),
                password: "password123".to_owned(),
                display_name: Some("Expired".to_owned()),
            },
            &test_ctx(),
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::GuestExpired));
}

#[tokio::test]
async fn convert_guest_creates_user_with_metadata_preserved() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, state) = make_app(&clock, false);

    let guest_result = app.create_guest(CreateGuestCommand, &test_ctx()).await.unwrap();
    let guest_id = guest_result.guest.id;

    {
        let mut s = state.write().await;
        let guest = s.guests.get_mut(&guest_id.as_uuid()).unwrap();
        guest.metadata = aegis_core::Metadata::new(r#"{"source":"landing_page","referral":"abc123"}"#);
    }

    let auth = app
        .convert_guest(
            guest_id,
            GuestConvertCommand {
                email: Some("new@example.com".to_owned()),
                password: "password123".to_owned(),
                display_name: Some("New User".to_owned()),
            },
            &test_ctx(),
        )
        .await
        .unwrap();

    assert!(auth.session_token.starts_with("tok-"));

    let s = state.read().await;

    let guest = s.guests.get(&guest_id.as_uuid()).unwrap();
    assert_eq!(guest.status, GuestStatus::Converted);
    assert!(guest.converted_to.is_some());

    let user_id = guest.converted_to.unwrap();
    let user = s.users.get(&user_id.as_uuid()).unwrap();
    assert_eq!(user.email.as_str(), "new@example.com");
    assert_eq!(user.display_name.as_str(), "New User");
    assert_eq!(user.metadata.as_str(), r#"{"source":"landing_page","referral":"abc123"}"#);

    assert!(s.credentials_password.contains_key(&user_id.as_uuid()));

    let convert_audit = s.audits.iter().find(|a| a.event_type == "guest.convert").unwrap();
    assert!(matches!(convert_audit.actor, Actor::Guest(_)));
    assert_eq!(convert_audit.target.as_ref().unwrap().target_type, "user");
    assert_eq!(convert_audit.target.as_ref().unwrap().target_id, Some(user_id.as_uuid()));
}

#[tokio::test]
async fn convert_guest_uses_guest_email_when_none_provided() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, _) = make_app(&clock, false);

    let guest_result = app.create_guest(CreateGuestCommand, &test_ctx()).await.unwrap();
    let guest_id = guest_result.guest.id;

    app.associate_guest_email(
        guest_id,
        GuestEmailCommand { email: "attached@example.com".to_owned() },
        &test_ctx(),
    )
    .await
    .unwrap();

    let auth = app
        .convert_guest(
            guest_id,
            GuestConvertCommand {
                email: None,
                password: "password123".to_owned(),
                display_name: Some("From Guest".to_owned()),
            },
            &test_ctx(),
        )
        .await
        .unwrap();

    assert_eq!(auth.user.email.as_str(), "attached@example.com");
}

#[tokio::test]
async fn convert_guest_fails_without_email() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, _) = make_app(&clock, false);

    let guest_result = app.create_guest(CreateGuestCommand, &test_ctx()).await.unwrap();
    let guest_id = guest_result.guest.id;

    let result = app
        .convert_guest(
            guest_id,
            GuestConvertCommand {
                email: None,
                password: "password123".to_owned(),
                display_name: Some("No Email".to_owned()),
            },
            &test_ctx(),
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::Validation(_)));
}

#[tokio::test]
async fn convert_guest_fails_with_duplicate_email() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, _) = make_app(&clock, false);

    app.signup(
        SignupCommand {
            email: "taken@example.com".to_owned(),
            password: "password123".to_owned(),
            display_name: "Existing".to_owned(),
        },
        &test_ctx(),
    )
    .await
    .unwrap();

    let guest_result = app.create_guest(CreateGuestCommand, &test_ctx()).await.unwrap();
    let guest_id = guest_result.guest.id;

    let result = app
        .convert_guest(
            guest_id,
            GuestConvertCommand {
                email: Some("taken@example.com".to_owned()),
                password: "password123".to_owned(),
                display_name: Some("Duplicate".to_owned()),
            },
            &test_ctx(),
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::EmailAlreadyExists));
}

#[tokio::test]
async fn get_guest_identity_returns_guest() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, _) = make_app(&clock, false);

    let guest_result = app.create_guest(CreateGuestCommand, &test_ctx()).await.unwrap();
    let guest_id = guest_result.guest.id;

    let identity = app.get_guest_identity(guest_id).await.unwrap();

    assert!(identity.user.is_none());
    assert!(identity.guest.is_some());
    assert_eq!(identity.guest.unwrap().id, guest_id);
    assert!(identity.roles.is_empty());
    assert!(identity.credentials.is_empty());
}

#[tokio::test]
async fn get_guest_identity_not_found() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, _) = make_app(&clock, false);

    let fake_id = aegis_core::GuestId::new();
    let result = app.get_guest_identity(fake_id).await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::NotFound(_)));
}

#[tokio::test]
async fn convert_guest_is_one_way() {
    let now = OffsetDateTime::now_utc();
    let clock = MockClock::new(now);
    let (app, state) = make_app(&clock, false);

    let guest_result = app.create_guest(CreateGuestCommand, &test_ctx()).await.unwrap();
    let guest_id = guest_result.guest.id;

    app.convert_guest(
        guest_id,
        GuestConvertCommand {
            email: Some("oneway@example.com".to_owned()),
            password: "password123".to_owned(),
            display_name: Some("One Way".to_owned()),
        },
        &test_ctx(),
    )
    .await
    .unwrap();

    let s = state.read().await;
    let guest = s.guests.get(&guest_id.as_uuid()).unwrap();
    assert_eq!(guest.status, GuestStatus::Converted);
    assert!(guest.converted_to.is_some());

    let user_id = guest.converted_to.unwrap();
    assert!(s.users.contains_key(&user_id.as_uuid()));
}
