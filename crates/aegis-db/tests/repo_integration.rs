use std::{env, path::PathBuf, sync::OnceLock};

use aegis_app::{
    AppError, AuditRepo, CredentialRepo, GuestRepo, OutboxRepo,
    PendingTokenRepo, Repos, RoleRepo, SessionRepo, TransactionRepos, UserRepo,
};
use aegis_core::{
    ALL_VALID_PERMISSIONS, Actor, AuditTarget, DisplayName, EmailAddress,
    Guest, GuestId, Metadata, NewAuditEntry, PasskeyCredential,
    PasskeyCredentialId, PasswordCredential, PasswordCredentialId,
    PendingToken, PendingTokenPurpose, RecoveryCode, RecoveryCodeId,
    RecoveryCodeState, Session, SessionId, SessionIdentity, TotpAlgorithm,
    TotpCredential, TotpCredentialId, User, UserId, UserStatus,
};
use aegis_db::repo::PgRepos;
use aegis_migrate::MigrationRunner;
use sqlx::PgPool;
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;
use uuid::Uuid;

fn test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn migrations_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../migrations")
}

async fn test_pool() -> PgPool {
    dotenvy::dotenv().ok();
    let url =
        env::var("AEGIS_DATABASE_URL").expect("AEGIS_DATABASE_URL must be set");
    let pool = PgPool::connect(&url).await.expect("connect postgres");
    MigrationRunner::new(pool.clone(), migrations_dir())
        .up()
        .await
        .expect("run migrations");
    pool
}

async fn reset_db(pool: &PgPool) {
    sqlx::query(
        "TRUNCATE users, guests, sessions, password_credentials, passkey_credentials, totp_credentials, recovery_codes, roles, user_role_assignments, audit_logs, email_verification_tokens, password_reset_tokens, outbox RESTART IDENTITY CASCADE",
    )
    .execute(pool)
    .await
    .expect("truncate tables");
}

fn make_user(email: &str) -> User {
    let now = OffsetDateTime::now_utc();
    User::builder(
        UserId::new(),
        EmailAddress::parse(email).unwrap(),
        DisplayName::parse("Alice").unwrap(),
    )
    .status(UserStatus::Active)
    .metadata(Metadata::new(r#"{"plan":"pro"}"#))
    .created_at(now)
    .updated_at(now)
    .build()
    .unwrap()
}

fn make_guest() -> Guest {
    let now = OffsetDateTime::now_utc();
    Guest::builder(GuestId::new(), now + Duration::days(7))
        .email(EmailAddress::parse("guest@example.com").unwrap())
        .metadata(Metadata::new(r#"{"source":"test"}"#))
        .created_at(now)
        .updated_at(now)
        .build()
        .unwrap()
}

fn make_session(user_id: UserId) -> Session {
    let now = OffsetDateTime::now_utc();
    Session::builder(
        SessionId::new(),
        [7; 32],
        SessionIdentity::User(user_id),
        now + Duration::hours(1),
    )
    .last_seen_at(now)
    .mfa_verified(false)
    .user_agent("integration-test")
    .ip_address("127.0.0.1")
    .metadata(Metadata::new(r#"{"device":"web"}"#))
    .build()
}

#[tokio::test]
async fn user_repo_roundtrip_and_transaction_rollback() {
    let _guard = test_lock().lock().await;
    let pool = test_pool().await;
    reset_db(&pool).await;

    let repos = PgRepos::new(pool.clone());
    let user = make_user("user@example.com");
    let user_for_insert = user.clone();

    repos
        .with_transaction(|mut tx| async move {
            let result = async {
                tx.users().insert(&user_for_insert).await?;
                Ok(())
            }
            .await;
            (tx, result)
        })
        .await
        .unwrap();

    let fetched = repos
        .users()
        .get_by_email("USER@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fetched.email.as_str(), "user@example.com");
    assert!(
        repos
            .users()
            .email_exists("user@example.com")
            .await
            .unwrap()
    );

    let mut updated = fetched.clone();
    updated.change_display_name_at(
        DisplayName::parse("Alice Updated").unwrap(),
        OffsetDateTime::now_utc(),
    );
    repos
        .with_transaction(|mut tx| async move {
            let result = async {
                tx.users().update(&updated).await?;
                Ok(())
            }
            .await;
            (tx, result)
        })
        .await
        .unwrap();

    let fetched = repos.users().get_by_id(user.id).await.unwrap().unwrap();
    assert_eq!(fetched.display_name.as_str(), "Alice Updated");

    let dup = make_user("user@example.com");
    let dup_err = repos
        .with_transaction(|mut tx| async move {
            let result = tx.users().insert(&dup).await;
            (tx, result)
        })
        .await
        .unwrap_err();
    assert!(matches!(dup_err, AppError::Infrastructure(_)));

    let rollback_user = make_user("rollback@example.com");
    let rollback_err = repos
        .with_transaction(|mut tx| async move {
            let result: Result<(), AppError> = async {
                tx.users().insert(&rollback_user).await?;
                Err(AppError::Validation("force rollback".into()))
            }
            .await;
            (tx, result)
        })
        .await
        .unwrap_err();
    assert!(matches!(rollback_err, AppError::Validation(_)));
    assert!(
        repos
            .users()
            .get_by_email("rollback@example.com")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn guest_repo_roundtrip() {
    let _guard = test_lock().lock().await;
    let pool = test_pool().await;
    reset_db(&pool).await;

    let repos = PgRepos::new(pool);
    let guest = make_guest();
    let guest_for_insert = guest.clone();

    repos
        .with_transaction(|mut tx| async move {
            let result = async {
                tx.guests().insert(&guest_for_insert).await?;
                Ok(())
            }
            .await;
            (tx, result)
        })
        .await
        .unwrap();

    let fetched = repos.guests().get_by_id(guest.id).await.unwrap().unwrap();
    assert_eq!(fetched.email.unwrap().as_str(), "guest@example.com");
}

#[tokio::test]
async fn session_repo_roundtrip_and_delete() {
    let _guard = test_lock().lock().await;
    let pool = test_pool().await;
    reset_db(&pool).await;

    let repos = PgRepos::new(pool);
    let user = make_user("session-user@example.com");
    let session = make_session(user.id);
    let user_for_insert = user.clone();
    let session_for_insert = session.clone();

    repos
        .with_transaction(|mut tx| async move {
            let result = async {
                tx.users().insert(&user_for_insert).await?;
                tx.sessions().insert(&session_for_insert).await?;
                Ok(())
            }
            .await;
            (tx, result)
        })
        .await
        .unwrap();

    let fetched = repos
        .sessions()
        .get_by_token_hash(&session.token_hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fetched.id.as_uuid(), session.id.as_uuid());

    repos
        .with_transaction(|mut tx| async move {
            let result = async {
                tx.sessions().delete_by_user_id(user.id).await?;
                Ok(())
            }
            .await;
            (tx, result)
        })
        .await
        .unwrap();

    assert!(
        repos
            .sessions()
            .get_by_token_hash(&session.token_hash)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn credential_repo_roundtrip() {
    let _guard = test_lock().lock().await;
    let pool = test_pool().await;
    reset_db(&pool).await;

    let repos = PgRepos::new(pool);
    let user = make_user("cred-user@example.com");
    let user_id = user.id;
    let now = OffsetDateTime::now_utc();
    let password = PasswordCredential {
        id: PasswordCredentialId::new(),
        user_id: user.id,
        hash: "hash".into(),
        algorithm_version: 1,
        created_at: now,
        updated_at: now,
        last_used_at: None,
    };
    let totp = TotpCredential {
        id: TotpCredentialId::new(),
        user_id: user.id,
        secret_encrypted: vec![1, 2, 3],
        nonce: vec![4, 5, 6],
        algorithm: TotpAlgorithm::Sha1,
        digits: 6,
        period: 30,
        enabled: true,
        created_at: now,
        updated_at: now,
    };
    let passkey = PasskeyCredential {
        id: PasskeyCredentialId::new(),
        user_id: user.id,
        credential_id: "cred-1".into(),
        public_key: vec![7, 8],
        attestation_object: None,
        authenticator_data: vec![9, 10],
        sign_count: 0,
        transports: vec!["internal".into()],
        backup_eligible: false,
        backup_state: false,
        created_at: now,
        last_used_at: None,
    };
    let recovery_code = RecoveryCode {
        id: RecoveryCodeId::new(),
        user_id: user.id,
        code_hash: "recovery-hash".into(),
        state: RecoveryCodeState::Unused,
        created_at: now,
    };
    let user_for_insert = user.clone();
    let password_for_insert = password.clone();
    let totp_for_insert = totp.clone();
    let passkey_for_insert = passkey.clone();
    let recovery_code_for_insert = recovery_code.clone();

    repos
        .with_transaction(|mut tx| async move {
            let result = async {
                tx.users().insert(&user_for_insert).await?;
                tx.credentials()
                    .insert_password(&password_for_insert)
                    .await?;
                tx.credentials().insert_totp(&totp_for_insert).await?;
                tx.credentials().insert_passkey(&passkey_for_insert).await?;
                tx.credentials()
                    .insert_recovery_codes(std::slice::from_ref(
                        &recovery_code_for_insert,
                    ))
                    .await?;
                Ok(())
            }
            .await;
            (tx, result)
        })
        .await
        .unwrap();

    assert!(
        repos
            .credentials()
            .get_password_by_user_id(user_id)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        repos
            .credentials()
            .get_totp_by_user_id(user_id)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        repos
            .credentials()
            .get_passkey_by_credential_id("cred-1")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        repos
            .credentials()
            .get_recovery_code_by_hash("recovery-hash")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        repos
            .credentials()
            .list_by_user_id(user_id)
            .await
            .unwrap()
            .len(),
        3
    );

    repos
        .with_transaction(|mut tx| async move {
            let result = async {
                tx.credentials().delete_by_id(passkey.id.as_uuid()).await?;
                tx.credentials()
                    .delete_recovery_codes_by_user_id(user.id)
                    .await?;
                Ok(())
            }
            .await;
            (tx, result)
        })
        .await
        .unwrap();

    assert!(
        repos
            .credentials()
            .get_passkey_by_credential_id("cred-1")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repos
            .credentials()
            .get_recovery_code_by_hash("recovery-hash")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn role_repo_reads_assignments() {
    let _guard = test_lock().lock().await;
    let pool = test_pool().await;
    reset_db(&pool).await;

    let repos = PgRepos::new(pool.clone());
    let user = make_user("role-user@example.com");
    let user_id = user.id;
    let user_for_insert = user.clone();
    let role_id = Uuid::now_v7();
    let permission = ALL_VALID_PERMISSIONS[0].to_string();

    repos
        .with_transaction(|mut tx| async move {
            let result = async {
                tx.users().insert(&user_for_insert).await?;
                Ok(())
            }
            .await;
            (tx, result)
        })
        .await
        .unwrap();

    sqlx::query(
        "INSERT INTO roles (id, name, description, permissions, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(role_id)
    .bind("admin")
    .bind(Some("administrator"))
    .bind(serde_json::json!([permission]))
    .bind(OffsetDateTime::now_utc())
    .bind(OffsetDateTime::now_utc())
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO user_role_assignments (id, user_id, role_id, granted_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(Uuid::now_v7())
    .bind(user_id.as_uuid())
    .bind(role_id)
    .bind(OffsetDateTime::now_utc())
    .execute(&pool)
    .await
    .unwrap();

    let roles = repos.roles().get_roles_by_user_id(user_id).await.unwrap();
    let assignments = repos
        .roles()
        .get_assignments_by_user_id(user_id)
        .await
        .unwrap();
    assert_eq!(roles.len(), 1);
    assert_eq!(assignments.len(), 1);
}

#[tokio::test]
async fn pending_token_repo_roundtrip() {
    let _guard = test_lock().lock().await;
    let pool = test_pool().await;
    reset_db(&pool).await;

    let repos = PgRepos::new(pool);
    let user = make_user("token-user@example.com");
    let token = PendingToken {
        id: uuid::Uuid::now_v7(),
        token_hash: [9; 32],
        user_id: user.id,
        purpose: PendingTokenPurpose::EmailVerification,
        expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
        created_at: OffsetDateTime::now_utc(),
    };
    let user_for_insert = user.clone();
    let token_for_insert = token.clone();

    repos
        .with_transaction(|mut tx| async move {
            let result = async {
                tx.users().insert(&user_for_insert).await?;
                tx.tokens().insert(&token_for_insert).await?;
                Ok(())
            }
            .await;
            (tx, result)
        })
        .await
        .unwrap();

    assert!(
        repos
            .tokens()
            .get_by_hash(&token.token_hash, token.purpose)
            .await
            .unwrap()
            .is_some()
    );

    repos
        .with_transaction(|mut tx| async move {
            let result = async {
                tx.tokens().delete_by_hash(&token.token_hash).await?;
                Ok(())
            }
            .await;
            (tx, result)
        })
        .await
        .unwrap();

    assert!(
        repos
            .tokens()
            .get_by_hash(&token.token_hash, token.purpose)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn audit_and_outbox_repos_roundtrip() {
    let _guard = test_lock().lock().await;
    let pool = test_pool().await;
    reset_db(&pool).await;

    let repos = PgRepos::new(pool.clone());
    let user = make_user("audit-user@example.com");
    let user_for_insert = user.clone();

    repos
        .with_transaction(|mut tx| async move {
            let result = async {
                tx.users().insert(&user_for_insert).await?;
                tx.audit()
                    .insert(&NewAuditEntry {
                        event_type: "user.login.success".into(),
                        actor: Actor::User(user.id),
                        target: Some(AuditTarget {
                            target_type: "user".into(),
                            target_id: Some(user.id.as_uuid()),
                        }),
                        ip_address: Some("127.0.0.1".into()),
                        user_agent: Some("integration-test".into()),
                        request_id: Some(Uuid::now_v7()),
                        metadata: Metadata::new(r#"{"ok":true}"#),
                        created_at: OffsetDateTime::now_utc(),
                    })
                    .await?;
                tx.outbox()
                    .enqueue(&aegis_app::JobPayload::SendVerificationEmail {
                        user_id: user.id.as_uuid(),
                        email: user.email.as_str().into(),
                        token: "verify-token".into(),
                    })
                    .await?;
                Ok(())
            }
            .await;
            (tx, result)
        })
        .await
        .unwrap();

    let audit_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(audit_count, 1);

    let claimed = repos
        .with_transaction(|mut tx| async move {
            let result = async {
                let claimed = tx.outbox().claim_pending(10).await?;
                tx.outbox().mark_processed(claimed[0].id).await?;
                Ok(claimed)
            }
            .await;
            (tx, result)
        })
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1);

    let status: String =
        sqlx::query_scalar("SELECT status FROM outbox WHERE id = $1")
            .bind(claimed[0].id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(status, "completed");
}
