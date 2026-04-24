mod common;

use reqwest::StatusCode;
use serde_json::Value;

use common::*;

const PASSWORD: &str = "Password123!Test";

#[tokio::test]
async fn internal_health_requires_valid_token() {
    let _guard = test_lock().lock().await;
    let pool = pg_pool().await;
    reset_db(&pool).await;
    let _server = spawn_test_server().await;

    let unauthorized = validate_session("missing", None).await;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let wrong = validate_session("missing", Some("Bearer wrong-token")).await;
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);

    let healthy = http_client()
        .get(format!("{SERVER_URL}/v1/internal/health"))
        .bearer_auth(internal_token())
        .send()
        .await
        .expect("health request");
    assert_eq!(healthy.status(), StatusCode::OK);

    let body = healthy.json::<Value>().await.expect("health json");
    assert_eq!(body["data"]["status"], "healthy");
    assert_eq!(body["data"]["emailEnabled"], true);
}

#[tokio::test]
async fn signup_verify_login_session_lifecycle_and_audit_logs_work() {
    let _guard = test_lock().lock().await;
    let pool = pg_pool().await;
    reset_db(&pool).await;
    let _server = spawn_test_server().await;

    let (client, jar) = cookie_client();
    let email = test_email("lifecycle");

    let signup_response = signup(&client, &email, PASSWORD).await;
    assert_eq!(signup_response.status(), StatusCode::OK);
    let signup_cookie =
        extract_set_cookie(&signup_response).expect("signup set-cookie");
    assert!(signup_cookie.contains("aegis_session="));
    let signup_body =
        signup_response.json::<Value>().await.expect("signup json");
    assert_eq!(signup_body["data"]["identity"]["type"], "user");
    assert_eq!(
        signup_body["data"]["identity"]["user"]["status"],
        "pendingverification"
    );

    let duplicate = signup(&client, &email, PASSWORD).await;
    assert_eq!(duplicate.status(), StatusCode::CONFLICT);
    let duplicate_body =
        duplicate.json::<Value>().await.expect("duplicate json");
    assert_api_error_code(
        &duplicate_body,
        StatusCode::CONFLICT,
        "USER_ALREADY_EXISTS",
    );

    let login_before_verify = login(&client, &email, PASSWORD).await;
    assert_eq!(login_before_verify.status(), StatusCode::FORBIDDEN);
    let login_before_verify_body = login_before_verify
        .json::<Value>()
        .await
        .expect("unverified login json");
    assert_api_error_code(
        &login_before_verify_body,
        StatusCode::FORBIDDEN,
        "AUTH_EMAIL_NOT_VERIFIED",
    );

    let verification_token = wait_for_mailpit_token(
        &email,
        "Use this verification token to verify your account: ",
    )
    .await;
    let verify_response = verify_email(&verification_token).await;
    assert_eq!(verify_response.status(), StatusCode::OK);

    let wrong_password = login(&client, &email, "WrongPassword123!").await;
    assert_eq!(wrong_password.status(), StatusCode::UNAUTHORIZED);
    let wrong_password_body = wrong_password
        .json::<Value>()
        .await
        .expect("wrong password json");
    assert_api_error_code(
        &wrong_password_body,
        StatusCode::UNAUTHORIZED,
        "AUTH_INVALID_CREDENTIALS",
    );

    let login_response = login(&client, &email, PASSWORD).await;
    assert_eq!(login_response.status(), StatusCode::OK);
    let login_cookie =
        extract_set_cookie(&login_response).expect("login set-cookie");
    assert!(login_cookie.contains("HttpOnly"));
    let login_body = login_response.json::<Value>().await.expect("login json");
    assert_eq!(login_body["data"]["status"], "authenticated");

    let session_token =
        session_cookie_value(&jar).expect("session cookie token");

    let me_response = me(&client).await;
    assert_eq!(me_response.status(), StatusCode::OK);
    let me_body = me_response.json::<Value>().await.expect("me json");
    assert_eq!(me_body["data"]["type"], "user");
    assert_eq!(me_body["data"]["user"]["email"], email);

    let missing_session = me(&http_client()).await;
    assert_eq!(missing_session.status(), StatusCode::UNAUTHORIZED);

    let valid_session = validate_session(
        &session_token,
        Some(&format!("Bearer {}", internal_token())),
    )
    .await;
    assert_eq!(valid_session.status(), StatusCode::OK);
    let valid_body = valid_session
        .json::<Value>()
        .await
        .expect("validate session json");
    assert_eq!(valid_body["data"]["valid"], true);
    assert!(valid_body["data"]["userId"].as_str().is_some());

    let logout_response = logout(&client).await;
    assert_eq!(logout_response.status(), StatusCode::OK);

    let post_logout_me = me(&client).await;
    assert_eq!(post_logout_me.status(), StatusCode::UNAUTHORIZED);

    let post_logout_validate = validate_session(
        &session_token,
        Some(&format!("Bearer {}", internal_token())),
    )
    .await;
    assert_eq!(post_logout_validate.status(), StatusCode::OK);
    let post_logout_body = post_logout_validate
        .json::<Value>()
        .await
        .expect("post logout validate json");
    assert_eq!(post_logout_body["data"]["valid"], false);

    let signup_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE event_type = 'user.signup'",
    )
    .fetch_one(&pool)
    .await
    .expect("signup audit count");
    let login_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE event_type = 'user.login'",
    )
    .fetch_one(&pool)
    .await
    .expect("login audit count");
    let logout_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE event_type = 'session.logout'",
    )
    .fetch_one(&pool)
    .await
    .expect("logout audit count");

    assert_eq!(signup_count, 1);
    assert_eq!(login_count, 1);
    assert_eq!(logout_count, 1);
}

#[tokio::test]
async fn forgot_password_creates_reset_record_and_emits_mail() {
    let _guard = test_lock().lock().await;
    let pool = pg_pool().await;
    reset_db(&pool).await;
    let _server = spawn_test_server().await;

    let (client, _) = cookie_client();
    let email = test_email("forgot-password");

    let signup_response = signup(&client, &email, PASSWORD).await;
    assert_eq!(signup_response.status(), StatusCode::OK);

    let verification_token = wait_for_mailpit_token(
        &email,
        "Use this verification token to verify your account: ",
    )
    .await;
    let verify_response = verify_email(&verification_token).await;
    assert_eq!(verify_response.status(), StatusCode::OK);

    let forgot = http_client()
        .post(format!("{SERVER_URL}/v1/auth/password/forgot"))
        .json(&serde_json::json!({ "email": email }))
        .send()
        .await
        .expect("forgot password request");
    assert_eq!(forgot.status(), StatusCode::OK);

    let reset_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM password_reset_tokens")
            .fetch_one(&pool)
            .await
            .expect("password reset token count");
    assert_eq!(reset_rows, 1);

    let reset_token = wait_for_mailpit_token(
        &email,
        "Use this password reset token to reset your password: ",
    )
    .await;
    assert!(!reset_token.is_empty());
}
