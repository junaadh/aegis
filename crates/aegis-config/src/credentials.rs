use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct CredentialsConfig {
    #[serde(default)]
    pub password: PasswordConfig,
    #[serde(default)]
    pub passkeys: PasskeysConfig,
    #[serde(default)]
    pub mfa: MfaConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PasswordConfig {
    #[serde(default = "default_hashing_algo")]
    pub hashing_algorithm: String,
    #[serde(default)]
    pub argon2: Argon2Config,
    #[serde(default)]
    pub policy: PasswordPolicyConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Argon2Config {
    #[serde(default = "default_argon2_time")]
    pub time_cost: u32,
    #[serde(default = "default_argon2_memory")]
    pub memory_cost: u32,
    #[serde(default = "default_argon2_parallelism")]
    pub parallelism: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PasswordPolicyConfig {
    #[serde(default = "default_min_length")]
    pub min_length: usize,
    #[serde(default = "default_true")]
    pub require_uppercase: bool,
    #[serde(default = "default_true")]
    pub require_lowercase: bool,
    #[serde(default = "default_true")]
    pub require_digit: bool,
    #[serde(default = "default_true")]
    pub require_symbol: bool,
    #[serde(default = "default_true")]
    pub disallow_common: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PasskeysConfig {
    #[serde(default)]
    pub rp_id: Option<String>,
    #[serde(default)]
    pub rp_name: Option<String>,
    #[serde(default)]
    pub origins: Vec<String>,
    #[serde(default = "default_user_verification")]
    pub user_verification: String,
    #[serde(default = "default_resident_key")]
    pub resident_key: String,
    #[serde(default = "default_passkey_timeout")]
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct MfaConfig {
    #[serde(default)]
    pub totp: TotpConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TotpConfig {
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default = "default_totp_period")]
    pub period: u32,
    #[serde(default = "default_totp_digits")]
    pub digits: u32,
    #[serde(default = "default_totp_algorithm")]
    pub algorithm: String,
    #[serde(default = "default_totp_skew")]
    pub skew: u32,
    #[serde(default)]
    pub recovery_codes: RecoveryCodesConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RecoveryCodesConfig {
    #[serde(default = "default_recovery_code_count")]
    pub count: u32,
    #[serde(default = "default_recovery_code_length")]
    pub code_length: u32,
}

fn default_true() -> bool {
    true
}

fn default_hashing_algo() -> String {
    "argon2id".to_owned()
}

fn default_argon2_time() -> u32 {
    3
}

fn default_argon2_memory() -> u32 {
    65536
}

fn default_argon2_parallelism() -> u32 {
    2
}

fn default_min_length() -> usize {
    12
}

fn default_user_verification() -> String {
    "preferred".to_owned()
}

fn default_resident_key() -> String {
    "preferred".to_owned()
}

fn default_passkey_timeout() -> u64 {
    60
}

fn default_totp_period() -> u32 {
    30
}

fn default_totp_digits() -> u32 {
    6
}

fn default_totp_algorithm() -> String {
    "SHA1".to_owned()
}

fn default_totp_skew() -> u32 {
    1
}

fn default_recovery_code_count() -> u32 {
    10
}

fn default_recovery_code_length() -> u32 {
    12
}


impl Default for PasswordConfig {
    fn default() -> Self {
        Self {
            hashing_algorithm: default_hashing_algo(),
            argon2: Argon2Config::default(),
            policy: PasswordPolicyConfig::default(),
        }
    }
}

impl Default for Argon2Config {
    fn default() -> Self {
        Self {
            time_cost: default_argon2_time(),
            memory_cost: default_argon2_memory(),
            parallelism: default_argon2_parallelism(),
        }
    }
}

impl Default for PasswordPolicyConfig {
    fn default() -> Self {
        Self {
            min_length: default_min_length(),
            require_uppercase: default_true(),
            require_lowercase: default_true(),
            require_digit: default_true(),
            require_symbol: default_true(),
            disallow_common: default_true(),
        }
    }
}

impl Default for PasskeysConfig {
    fn default() -> Self {
        Self {
            rp_id: None,
            rp_name: None,
            origins: Vec::new(),
            user_verification: default_user_verification(),
            resident_key: default_resident_key(),
            timeout_seconds: default_passkey_timeout(),
        }
    }
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            issuer: None,
            period: default_totp_period(),
            digits: default_totp_digits(),
            algorithm: default_totp_algorithm(),
            skew: default_totp_skew(),
            recovery_codes: RecoveryCodesConfig::default(),
        }
    }
}

impl Default for RecoveryCodesConfig {
    fn default() -> Self {
        Self {
            count: default_recovery_code_count(),
            code_length: default_recovery_code_length(),
        }
    }
}
