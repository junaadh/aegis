use crate::{Config, ConfigError, ConfigSrc, RefOr};

#[test]
fn default_config_serializes() {
    let config = Config::default();
    let toml_str = config.to_toml().unwrap();
    assert!(toml_str.contains("[server]"));
    assert!(toml_str.contains("[database]"));
    assert!(toml_str.contains("host = \"0.0.0.0\""));
    assert!(toml_str.contains("port = 8080"));
}

#[test]
fn deny_unknown_fields() {
    let toml_str = r#"
[server]
host = "0.0.0.0"
unknown_field = "should_fail"
"#;
    let result = Config::from_toml(toml_str);
    assert!(result.is_err());
    match result.unwrap_err() {
        ConfigError::Parse(e) => {
            let msg = e.to_string();
            assert!(msg.contains("unknown field") || msg.contains("unexpected"));
        }
        e => panic!("expected parse error, got: {e}"),
    }
}

#[test]
fn missing_database_fails_validation() {
    let toml_str = r#"
[server]
[session]
secret = "test-secret"
[credentials]
[api]
[crypto]
[compliance]
[webhooks]
[redis]

[email]
enabled = false
"#;
    let result = Config::from_toml(toml_str);
    assert!(result.is_err());
    match result.unwrap_err() {
        ConfigError::MissingField(field) => assert_eq!(field, "database"),
        e => panic!("expected missing database, got: {e}"),
    }
}

#[test]
fn missing_session_fails_validation() {
    let toml_str = r#"
[server]
[database]
url = "postgresql://localhost/test"
[credentials]
[api]
[crypto]
[compliance]
[webhooks]
[redis]

[email]
enabled = false
"#;
    let result = Config::from_toml(toml_str);
    assert!(result.is_err());
    match result.unwrap_err() {
        ConfigError::MissingField(field) => assert_eq!(field, "session"),
        e => panic!("expected missing session, got: {e}"),
    }
}

#[test]
fn ref_or_value_resolves() {
    let r: RefOr<String> = RefOr::Value("hello".to_owned());
    assert_eq!(r.resolve().unwrap(), "hello");
}

#[test]
fn ref_or_u16_resolves() {
    let r: RefOr<u16> = RefOr::Value(587);
    assert_eq!(r.resolve().unwrap(), 587);
}

#[test]
fn ref_or_env_resolves() {
    let r: RefOr<String> = RefOr::Env("TEST_AEGIS_REF_OR".to_owned());
    unsafe { std::env::set_var("TEST_AEGIS_REF_OR", "env-value-123") };
    assert_eq!(r.resolve().unwrap(), "env-value-123");
    unsafe { std::env::remove_var("TEST_AEGIS_REF_OR") };
}

#[test]
fn ref_or_env_missing_fails() {
    let r: RefOr<String> = RefOr::Env("NONEXISTENT_AEGIS_VAR_99999".to_owned());
    let result = r.resolve();
    assert!(result.is_err());
    match result.unwrap_err() {
        ConfigError::ResolveEnv { var } => assert_eq!(var, "NONEXISTENT_AEGIS_VAR_99999"),
        e => panic!("expected ResolveEnv, got: {e}"),
    }
}

#[test]
fn ref_or_file_resolves() {
    let dir = std::env::temp_dir().join("aegis_test_ref_or");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test_value.txt");
    std::fs::write(&path, "file-value-456\n").unwrap();

    let r: RefOr<String> = RefOr::File(path.to_str().unwrap().to_owned());
    assert_eq!(r.resolve().unwrap(), "file-value-456");

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn ref_or_file_missing_fails() {
    let r: RefOr<String> = RefOr::File("/nonexistent/path/value.txt".to_owned());
    let result = r.resolve();
    assert!(result.is_err());
    match result.unwrap_err() {
        ConfigError::ResolveFile { path, .. } => {
            assert_eq!(path, "/nonexistent/path/value.txt");
        }
        e => panic!("expected ResolveFile, got: {e}"),
    }
}

#[test]
fn ref_or_serde_roundtrip_value() {
    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Wrap {
        port: RefOr<u16>,
    }
    let w = Wrap { port: RefOr::Value(587) };
    let toml_str = toml::to_string(&w).unwrap();
    assert!(toml_str.contains("port = 587"));

    let parsed: Wrap = toml::from_str(&toml_str).unwrap();
    assert_eq!(parsed.port, RefOr::Value(587));
}

#[test]
fn ref_or_serde_roundtrip_env() {
    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Wrap {
        url: RefOr<String>,
    }
    let w = Wrap { url: RefOr::Env("MY_VAR".to_owned()) };
    let toml_str = toml::to_string(&w).unwrap();
    assert!(toml_str.contains("env:MY_VAR"));

    let parsed: Wrap = toml::from_str(&toml_str).unwrap();
    assert_eq!(parsed.url, RefOr::Env("MY_VAR".to_owned()));
}

#[test]
fn ref_or_serde_roundtrip_file() {
    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Wrap {
        key: RefOr<String>,
    }
    let w = Wrap { key: RefOr::File("/path/to/secret".to_owned()) };
    let toml_str = toml::to_string(&w).unwrap();
    assert!(toml_str.contains("file:/path/to/secret"));

    let parsed: Wrap = toml::from_str(&toml_str).unwrap();
    assert_eq!(parsed.key, RefOr::File("/path/to/secret".to_owned()));
}

#[test]
fn ref_or_bool_serde() {
    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Wrap {
        enabled: RefOr<bool>,
    }
    let w = Wrap { enabled: RefOr::Value(true) };
    let toml_str = toml::to_string(&w).unwrap();
    assert!(toml_str.contains("enabled = true"));

    let parsed: Wrap = toml::from_str(&toml_str).unwrap();
    assert_eq!(parsed.enabled, RefOr::Value(true));
}

#[test]
fn config_src_deserialize_with_env_refs() {
    let toml_str = r#"
[database]
url = "env:AEGIS_DATABASE_URL"
max_connections = 25

[session]
secret = "env:AEGIS_SESSION_SECRET"
max_age_hours = 168

[server]
[email]
enabled = false
[credentials]
[api]
[crypto]
[compliance]
[webhooks]
[redis]
"#;

    let source: ConfigSrc = toml::from_str(toml_str).unwrap();

    if let RefOr::Value(Some(db)) = &source.database {
        assert!(matches!(&db.url, RefOr::Env(v) if v == "AEGIS_DATABASE_URL"));
        assert!(matches!(&db.max_connections, RefOr::Value(25)));
    } else {
        panic!("expected database");
    }

    if let RefOr::Value(Some(session)) = &source.session {
        assert!(matches!(&session.secret, RefOr::Env(v) if v == "AEGIS_SESSION_SECRET"));
    } else {
        panic!("expected session");
    }
}

#[test]
fn config_src_serialize_preserves_refs() {
    let source = ConfigSrc::default();
    let toml_str = toml::to_string_pretty(&source).unwrap();

    assert!(toml_str.contains("env:AEGIS_DATABASE_URL"));
    assert!(toml_str.contains("env:AEGIS_SESSION_SECRET"));
}

#[test]
fn config_src_roundtrip() {
    let source = ConfigSrc::default();
    let toml_str = source.to_toml().unwrap();
    let parsed: ConfigSrc = toml::from_str(&toml_str).unwrap();
    let reparsed = parsed.to_toml().unwrap();
    assert_eq!(toml_str, reparsed);
}

#[test]
fn schema_generation_succeeds() {
    let schema = crate::schema::generate_schema();
    let json = serde_json::to_string_pretty(&schema).unwrap();
    assert!(json.contains("Config"));
    assert!(json.contains("server"));
    assert!(json.contains("database"));
    assert!(json.contains("session"));
    assert!(json.contains("oneOf"));
    assert!(!json.contains("anyOf"));
    assert!(json.contains("^env:.+"));
    assert!(json.contains("^file:.+"));
    assert!(json.contains("minimum"));
    assert!(json.contains("maximum"));
    assert!(json.contains("x-aegis-ref"));
    assert!(json.contains("^(?!env:)(?!file:).*$"));
}

#[test]
fn schema_no_fake_integer_formats() {
    let schema = crate::schema::generate_schema();
    let json = serde_json::to_string_pretty(&schema).unwrap();
    assert!(!json.contains("\"uint16\""));
    assert!(!json.contains("\"uint32\""));
    assert!(!json.contains("\"uint64\""));
    assert!(!json.contains("\"uint\""));
}

#[test]
fn schema_integer_constraints() {
    let schema = crate::schema::generate_schema();
    let json = serde_json::to_string_pretty(&schema).unwrap();

    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let defs = parsed["definitions"].as_object().unwrap();

    let server = &defs["ServerConfig"];
    let port = &server["properties"]["port"];
    let port_obj = port["oneOf"][0].as_object().unwrap();
    assert_eq!(port_obj.get("minimum").unwrap(), 0);
    assert_eq!(port_obj.get("maximum").unwrap(), 65535);
    assert!(port_obj.get("format").is_none());
}

#[test]
fn default_env_template_not_empty() {
    let template = Config::default_env_template();
    assert!(template.contains("AEGIS_SESSION_SECRET"));
    assert!(template.contains("AEGIS_DATABASE_URL"));
    assert!(template.contains("AEGIS_EMAIL_SMTP_PASSWORD"));
}

#[test]
fn config_email_defaults() {
    let config = Config::default();
    assert!(!config.email.enabled);
}

#[test]
fn config_session_defaults() {
    let config = Config::default();
    let session = config.session.unwrap();
    assert_eq!(session.max_age_hours, 168);
    assert_eq!(session.idle_timeout_minutes, 30);
}

#[test]
fn minimal_valid_config_validates() {
    let toml_str = r#"
[database]
url = "postgresql://localhost/test"
max_connections = 25

[session]
secret = "a-valid-secret"
max_age_hours = 168

[server]
[email]
enabled = false
[credentials]
[api]
[crypto]
[compliance]
[webhooks]
[redis]
"#;
    let config = Config::from_toml(toml_str).unwrap();
    config.validate().unwrap();
}

#[test]
fn full_config_loads_with_env_resolution() {
    let toml_str = r#"
[database]
url = "postgresql://aegis:aegis@localhost:5432/aegis_dev"
max_connections = 25

[session]
secret = "test-session-secret-for-testing"
max_age_hours = 168

[server]
[email]
enabled = false
[credentials]
[api]
[crypto]
[compliance]
[webhooks]
[redis]
"#;

    let config = Config::from_toml(toml_str).unwrap();
    assert_eq!(config.database.unwrap().url, "postgresql://aegis:aegis@localhost:5432/aegis_dev");
    assert_eq!(config.session.unwrap().secret, "test-session-secret-for-testing");
}

#[test]
fn config_loads_env_ref_with_var_set() {
    unsafe {
        std::env::set_var("TEST_AEGIS_DB_URL", "postgresql://test:test@localhost/testdb");
        std::env::set_var("TEST_AEGIS_SESSION", "my-session-secret");
    }

    let toml_str = r#"
[database]
url = "env:TEST_AEGIS_DB_URL"

[session]
secret = "env:TEST_AEGIS_SESSION"

[server]
[email]
enabled = false
[credentials]
[api]
[crypto]
[compliance]
[webhooks]
[redis]
"#;

    let config = Config::from_toml(toml_str).unwrap();
    assert_eq!(config.database.unwrap().url, "postgresql://test:test@localhost/testdb");
    assert_eq!(config.session.unwrap().secret, "my-session-secret");

    unsafe {
        std::env::remove_var("TEST_AEGIS_DB_URL");
        std::env::remove_var("TEST_AEGIS_SESSION");
    }
}

#[test]
fn ref_or_option_string_resolves() {
    let r: RefOr<Option<String>> = RefOr::Value(None);
    assert_eq!(r.resolve().unwrap(), None);

    let r: RefOr<Option<String>> = RefOr::Value(Some("hello".to_owned()));
    assert_eq!(r.resolve().unwrap(), Some("hello".to_owned()));
}

#[test]
fn ref_or_vec_string_resolves() {
    let r: RefOr<Vec<String>> = RefOr::Value(vec!["stdout".to_owned()]);
    assert_eq!(r.resolve().unwrap(), vec!["stdout".to_owned()]);
}

#[test]
fn ref_or_nested_resolves() {
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Inner {
        port: RefOr<u16>,
    }
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Outer {
        inner: RefOr<Inner>,
    }

    let o = Outer { inner: RefOr::Value(Inner { port: RefOr::Value(587) }) };
    let resolved = o.inner.resolve_nested(|i| i.port.resolve()).unwrap();
    assert_eq!(resolved, 587);
}
