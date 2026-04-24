use aegis_config::Config;
use aegis_core::PasswordPolicy;
use time::Duration;

use crate::error::AppError;

#[derive(Debug, Clone)]
pub struct AppPolicies {
    pub auth: AuthPolicy,
    pub email: EmailPolicy,
    pub crypto: CryptoPolicy,
    pub compliance: CompliancePolicy,
    pub totp: TotpPolicy,
    pub recovery_codes: RecoveryCodePolicy,
    pub passkeys: PasskeyPolicy,
}

#[derive(Debug, Clone)]
pub struct AuthPolicy {
    pub session_max_age: Duration,
    pub session_idle_timeout: Duration,
    pub allow_unverified_login: bool,
    pub password_policy: PasswordPolicy,
    pub bearer_token_length: usize,
    pub bearer_default_ttl: Duration,
    pub refresh_token_enabled: bool,
    pub refresh_token_ttl: Duration,
    pub revoke_all_sessions_on_password_reset: bool,
}

#[derive(Debug, Clone)]
pub struct EmailPolicy {
    pub enabled: bool,
    pub verification_token_ttl: Duration,
    pub password_reset_token_ttl: Duration,
}

#[derive(Debug, Clone)]
pub struct CryptoPolicy {
    pub master_key: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CompliancePolicy {
    pub guest_ttl: Duration,
    pub deleted_user_anonymize_after: Duration,
    pub anonymize_email_pattern: String,
}

#[derive(Debug, Clone)]
pub struct TotpPolicy {
    pub issuer: String,
    pub period: u32,
    pub digits: u32,
    pub algorithm: aegis_core::TotpAlgorithm,
    pub skew: u32,
}

#[derive(Debug, Clone)]
pub struct RecoveryCodePolicy {
    pub count: u32,
    pub code_length: u32,
}

#[derive(Debug, Clone)]
pub struct PasskeyPolicy {
    pub rp_id: Option<String>,
    pub rp_name: Option<String>,
    pub origins: Vec<String>,
    pub timeout_seconds: u64,
}

impl AppPolicies {
    pub fn from_config(cfg: &Config) -> Result<Self, AppError> {
        let session = cfg.session.as_ref().ok_or_else(|| {
            AppError::Validation("session config is required".to_owned())
        })?;

        let auth = AuthPolicy {
            session_max_age: Duration::hours(session.max_age_hours as i64),
            session_idle_timeout: Duration::minutes(
                session.idle_timeout_minutes as i64,
            ),
            allow_unverified_login: !cfg.email.enabled,
            password_policy: PasswordPolicy {
                min_length: cfg.credentials.password.policy.min_length,
                require_uppercase: cfg
                    .credentials
                    .password
                    .policy
                    .require_uppercase,
                require_lowercase: cfg
                    .credentials
                    .password
                    .policy
                    .require_lowercase,
                require_digit: cfg.credentials.password.policy.require_digit,
                require_symbol: cfg.credentials.password.policy.require_symbol,
                disallow_common: cfg
                    .credentials
                    .password
                    .policy
                    .disallow_common,
                disallow_email_substring: true,
            },
            bearer_token_length: session.bearer.opaque_token_length as usize,
            bearer_default_ttl: Duration::minutes(
                session.bearer.default_ttl_minutes as i64,
            ),
            refresh_token_enabled: session.bearer.refresh_token_enabled,
            refresh_token_ttl: Duration::days(
                session.bearer.refresh_token_ttl_days as i64,
            ),
            revoke_all_sessions_on_password_reset: true,
        };

        let email = EmailPolicy {
            enabled: cfg.email.enabled,
            verification_token_ttl: Duration::hours(
                cfg.email.verification_token_ttl_hours as i64,
            ),
            password_reset_token_ttl: Duration::minutes(
                cfg.email.password_reset_token_ttl_minutes as i64,
            ),
        };

        let crypto = CryptoPolicy {
            master_key: cfg.crypto.master_key.clone(),
        };

        let compliance = CompliancePolicy {
            guest_ttl: Duration::days(
                cfg.compliance.data_retention.guest_ttl_days as i64,
            ),
            deleted_user_anonymize_after: Duration::days(
                cfg.compliance
                    .data_retention
                    .deleted_user_anonymize_after_days as i64,
            ),
            anonymize_email_pattern: cfg
                .compliance
                .deletion
                .anonymize_email_pattern
                .clone(),
        };

        let totp = TotpPolicy {
            issuer: {
                let s = &cfg.credentials.mfa.totp.issuer;
                if s.is_empty() {
                    "Aegis".to_owned()
                } else {
                    s.clone()
                }
            },
            period: cfg.credentials.mfa.totp.period,
            digits: cfg.credentials.mfa.totp.digits,
            algorithm: match cfg.credentials.mfa.totp.algorithm {
                aegis_config::TotpAlgorithm::SHA1 => {
                    aegis_core::TotpAlgorithm::Sha1
                }
                aegis_config::TotpAlgorithm::SHA256 => {
                    aegis_core::TotpAlgorithm::Sha256
                }
                aegis_config::TotpAlgorithm::SHA512 => {
                    aegis_core::TotpAlgorithm::Sha512
                }
            },
            skew: cfg.credentials.mfa.totp.skew,
        };

        let recovery_codes = RecoveryCodePolicy {
            count: cfg.credentials.mfa.totp.recovery_codes.count,
            code_length: cfg.credentials.mfa.totp.recovery_codes.code_length,
        };

        let passkeys = PasskeyPolicy {
            rp_id: {
                let s = &cfg.credentials.passkeys.rp_id;
                if s.is_empty() { None } else { Some(s.clone()) }
            },
            rp_name: {
                let s = &cfg.credentials.passkeys.rp_name;
                if s.is_empty() { None } else { Some(s.clone()) }
            },
            origins: cfg.credentials.passkeys.origins.clone(),
            timeout_seconds: cfg.credentials.passkeys.timeout_seconds,
        };

        Ok(Self {
            auth,
            email,
            crypto,
            compliance,
            totp,
            recovery_codes,
            passkeys,
        })
    }
}
