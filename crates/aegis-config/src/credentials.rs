use crate::enums::{HashingAlgorithm, ResidentKey, TotpAlgorithm, UserVerification};
use crate::error::ConfigError;
use crate::ref_or::RefOr;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct CredentialsConfig {
    #[serde(default)]
    pub password: PasswordConfig,
    #[serde(default)]
    pub passkeys: PasskeysConfig,
    #[serde(default)]
    pub mfa: MfaConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct PasswordConfig {
    #[schemars(title = "Hashing algorithm", description = "Password hashing algorithm.")]
    #[serde(default)]
    pub hashing_algorithm: HashingAlgorithm,

    #[serde(default)]
    pub argon2: Argon2Config,

    #[serde(default)]
    pub policy: PasswordPolicyConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Argon2Config {
    #[schemars(title = "Time cost", description = "Argon2 time cost parameter.")]
    #[serde(default = "default_argon2_time")]
    pub time_cost: u32,

    #[schemars(title = "Memory cost", description = "Argon2 memory cost in KiB.")]
    #[serde(default = "default_argon2_memory")]
    pub memory_cost: u32,

    #[schemars(title = "Parallelism", description = "Argon2 parallelism parameter.")]
    #[serde(default = "default_argon2_parallelism")]
    pub parallelism: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PasswordPolicyConfig {
    #[schemars(title = "Minimum length", description = "Minimum password length.")]
    #[serde(default = "default_min_length")]
    pub min_length: usize,

    #[schemars(title = "Require uppercase", description = "Require at least one uppercase letter.")]
    #[serde(default = "default_true")]
    pub require_uppercase: bool,

    #[schemars(title = "Require lowercase", description = "Require at least one lowercase letter.")]
    #[serde(default = "default_true")]
    pub require_lowercase: bool,

    #[schemars(title = "Require digit", description = "Require at least one digit.")]
    #[serde(default = "default_true")]
    pub require_digit: bool,

    #[schemars(title = "Require symbol", description = "Require at least one symbol.")]
    #[serde(default = "default_true")]
    pub require_symbol: bool,

    #[schemars(title = "Disallow common", description = "Disallow commonly used passwords.")]
    #[serde(default = "default_true")]
    pub disallow_common: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PasskeysConfig {
    #[schemars(title = "Relying party ID", description = "WebAuthn relying party identifier.")]
    #[serde(default)]
    pub rp_id: String,

    #[schemars(title = "Relying party name", description = "Human-readable relying party name.")]
    #[serde(default)]
    pub rp_name: String,

    #[schemars(title = "Origins", description = "Allowed origins for WebAuthn.")]
    #[serde(default)]
    pub origins: Vec<String>,

    #[schemars(title = "User verification", description = "WebAuthn user verification requirement.")]
    #[serde(default)]
    pub user_verification: UserVerification,

    #[schemars(title = "Resident key", description = "WebAuthn resident key requirement.")]
    #[serde(default)]
    pub resident_key: ResidentKey,

    #[schemars(title = "Timeout", description = "WebAuthn ceremony timeout in seconds.")]
    #[serde(default = "default_passkey_timeout")]
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct MfaConfig {
    #[serde(default)]
    pub totp: TotpConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TotpConfig {
    #[schemars(title = "Issuer", description = "TOTP issuer name shown in authenticator apps.")]
    #[serde(default)]
    pub issuer: String,

    #[schemars(title = "Period", description = "TOTP time step in seconds.")]
    #[serde(default = "default_totp_period")]
    pub period: u32,

    #[schemars(title = "Digits", description = "Number of TOTP digits.")]
    #[serde(default = "default_totp_digits")]
    pub digits: u32,

    #[schemars(title = "Algorithm", description = "TOTP HMAC algorithm.")]
    #[serde(default)]
    pub algorithm: TotpAlgorithm,

    #[schemars(title = "Skew", description = "Allowed TOTP time skew (periods before/after).")]
    #[serde(default = "default_totp_skew")]
    pub skew: u32,

    #[serde(default)]
    pub recovery_codes: RecoveryCodesConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCodesConfig {
    #[schemars(title = "Count", description = "Number of recovery codes to generate.")]
    #[serde(default = "default_recovery_code_count")]
    pub count: u32,

    #[schemars(title = "Code length", description = "Length of each recovery code.")]
    #[serde(default = "default_recovery_code_length")]
    pub code_length: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[derive(Default)]
pub struct CredentialsConfigSrc {
    #[serde(default)]
    pub password: RefOr<PasswordConfigSrc>,
    #[serde(default)]
    pub passkeys: RefOr<PasskeysConfigSrc>,
    #[serde(default)]
    pub mfa: RefOr<MfaConfigSrc>,
}

impl CredentialsConfigSrc {
    pub fn resolve(&self) -> Result<CredentialsConfig, ConfigError> {
        Ok(CredentialsConfig {
            password: self.password.resolve_nested(|s| s.resolve())?,
            passkeys: self.passkeys.resolve_nested(|s| s.resolve())?,
            mfa: self.mfa.resolve_nested(|s| s.resolve())?,
        })
    }
}


#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[derive(Default)]
pub struct PasswordConfigSrc {
    #[schemars(title = "Hashing algorithm", description = "Password hashing algorithm.")]
    #[serde(default)]
    pub hashing_algorithm: RefOr<HashingAlgorithm>,

    #[serde(default)]
    pub argon2: RefOr<Argon2ConfigSrc>,

    #[serde(default)]
    pub policy: RefOr<PasswordPolicyConfigSrc>,
}

impl PasswordConfigSrc {
    pub fn resolve(&self) -> Result<PasswordConfig, ConfigError> {
        Ok(PasswordConfig {
            hashing_algorithm: self.hashing_algorithm.resolve()?,
            argon2: self.argon2.resolve_nested(|s| s.resolve())?,
            policy: self.policy.resolve_nested(|s| s.resolve())?,
        })
    }
}


#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Argon2ConfigSrc {
    #[schemars(title = "Time cost", description = "Argon2 time cost parameter.")]
    #[serde(default = "default_argon2_time_or")]
    pub time_cost: RefOr<u32>,

    #[schemars(title = "Memory cost", description = "Argon2 memory cost in KiB.")]
    #[serde(default = "default_argon2_memory_or")]
    pub memory_cost: RefOr<u32>,

    #[schemars(title = "Parallelism", description = "Argon2 parallelism parameter.")]
    #[serde(default = "default_argon2_parallelism_or")]
    pub parallelism: RefOr<u32>,
}

impl Argon2ConfigSrc {
    pub fn resolve(&self) -> Result<Argon2Config, ConfigError> {
        Ok(Argon2Config {
            time_cost: self.time_cost.resolve()?,
            memory_cost: self.memory_cost.resolve()?,
            parallelism: self.parallelism.resolve()?,
        })
    }
}

impl Default for Argon2ConfigSrc {
    fn default() -> Self {
        Self {
            time_cost: default_argon2_time_or(),
            memory_cost: default_argon2_memory_or(),
            parallelism: default_argon2_parallelism_or(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PasswordPolicyConfigSrc {
    #[schemars(title = "Minimum length", description = "Minimum password length.")]
    #[serde(default = "default_min_length_or")]
    pub min_length: RefOr<usize>,

    #[schemars(title = "Require uppercase", description = "Require at least one uppercase letter.")]
    #[serde(default = "default_true_or")]
    pub require_uppercase: RefOr<bool>,

    #[schemars(title = "Require lowercase", description = "Require at least one lowercase letter.")]
    #[serde(default = "default_true_or")]
    pub require_lowercase: RefOr<bool>,

    #[schemars(title = "Require digit", description = "Require at least one digit.")]
    #[serde(default = "default_true_or")]
    pub require_digit: RefOr<bool>,

    #[schemars(title = "Require symbol", description = "Require at least one symbol.")]
    #[serde(default = "default_true_or")]
    pub require_symbol: RefOr<bool>,

    #[schemars(title = "Disallow common", description = "Disallow commonly used passwords.")]
    #[serde(default = "default_true_or")]
    pub disallow_common: RefOr<bool>,
}

impl PasswordPolicyConfigSrc {
    pub fn resolve(&self) -> Result<PasswordPolicyConfig, ConfigError> {
        Ok(PasswordPolicyConfig {
            min_length: self.min_length.resolve()?,
            require_uppercase: self.require_uppercase.resolve()?,
            require_lowercase: self.require_lowercase.resolve()?,
            require_digit: self.require_digit.resolve()?,
            require_symbol: self.require_symbol.resolve()?,
            disallow_common: self.disallow_common.resolve()?,
        })
    }
}

impl Default for PasswordPolicyConfigSrc {
    fn default() -> Self {
        Self {
            min_length: default_min_length_or(),
            require_uppercase: default_true_or(),
            require_lowercase: default_true_or(),
            require_digit: default_true_or(),
            require_symbol: default_true_or(),
            disallow_common: default_true_or(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PasskeysConfigSrc {
    #[schemars(title = "Relying party ID", description = "WebAuthn relying party identifier.")]
    #[serde(default)]
    pub rp_id: RefOr<String>,

    #[schemars(title = "Relying party name", description = "Human-readable relying party name.")]
    #[serde(default)]
    pub rp_name: RefOr<String>,

    #[schemars(title = "Origins", description = "Allowed origins for WebAuthn.")]
    #[serde(default)]
    pub origins: RefOr<Vec<String>>,

    #[schemars(title = "User verification", description = "WebAuthn user verification requirement.")]
    #[serde(default)]
    pub user_verification: RefOr<UserVerification>,

    #[schemars(title = "Resident key", description = "WebAuthn resident key requirement.")]
    #[serde(default)]
    pub resident_key: RefOr<ResidentKey>,

    #[schemars(title = "Timeout", description = "WebAuthn ceremony timeout in seconds.")]
    #[serde(default = "default_passkey_timeout_or")]
    pub timeout_seconds: RefOr<u64>,
}

impl PasskeysConfigSrc {
    pub fn resolve(&self) -> Result<PasskeysConfig, ConfigError> {
        Ok(PasskeysConfig {
            rp_id: self.rp_id.resolve()?,
            rp_name: self.rp_name.resolve()?,
            origins: self.origins.resolve()?,
            user_verification: self.user_verification.resolve()?,
            resident_key: self.resident_key.resolve()?,
            timeout_seconds: self.timeout_seconds.resolve()?,
        })
    }
}

impl Default for PasskeysConfigSrc {
    fn default() -> Self {
        Self {
            rp_id: RefOr::default(),
            rp_name: RefOr::default(),
            origins: RefOr::default(),
            user_verification: RefOr::default(),
            resident_key: RefOr::default(),
            timeout_seconds: default_passkey_timeout_or(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[derive(Default)]
pub struct MfaConfigSrc {
    #[serde(default)]
    pub totp: RefOr<TotpConfigSrc>,
}

impl MfaConfigSrc {
    pub fn resolve(&self) -> Result<MfaConfig, ConfigError> {
        Ok(MfaConfig {
            totp: self.totp.resolve_nested(|s| s.resolve())?,
        })
    }
}


#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TotpConfigSrc {
    #[schemars(title = "Issuer", description = "TOTP issuer name shown in authenticator apps.")]
    #[serde(default)]
    pub issuer: RefOr<String>,

    #[schemars(title = "Period", description = "TOTP time step in seconds.")]
    #[serde(default = "default_totp_period_or")]
    pub period: RefOr<u32>,

    #[schemars(title = "Digits", description = "Number of TOTP digits.")]
    #[serde(default = "default_totp_digits_or")]
    pub digits: RefOr<u32>,

    #[schemars(title = "Algorithm", description = "TOTP HMAC algorithm.")]
    #[serde(default)]
    pub algorithm: RefOr<TotpAlgorithm>,

    #[schemars(title = "Skew", description = "Allowed TOTP time skew (periods before/after).")]
    #[serde(default = "default_totp_skew_or")]
    pub skew: RefOr<u32>,

    #[serde(default)]
    pub recovery_codes: RefOr<RecoveryCodesConfigSrc>,
}

impl TotpConfigSrc {
    pub fn resolve(&self) -> Result<TotpConfig, ConfigError> {
        Ok(TotpConfig {
            issuer: self.issuer.resolve()?,
            period: self.period.resolve()?,
            digits: self.digits.resolve()?,
            algorithm: self.algorithm.resolve()?,
            skew: self.skew.resolve()?,
            recovery_codes: self.recovery_codes.resolve_nested(|s| s.resolve())?,
        })
    }
}

impl Default for TotpConfigSrc {
    fn default() -> Self {
        Self {
            issuer: RefOr::default(),
            period: default_totp_period_or(),
            digits: default_totp_digits_or(),
            algorithm: RefOr::default(),
            skew: default_totp_skew_or(),
            recovery_codes: RefOr::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCodesConfigSrc {
    #[schemars(title = "Count", description = "Number of recovery codes to generate.")]
    #[serde(default = "default_recovery_code_count_or")]
    pub count: RefOr<u32>,

    #[schemars(title = "Code length", description = "Length of each recovery code.")]
    #[serde(default = "default_recovery_code_length_or")]
    pub code_length: RefOr<u32>,
}

impl RecoveryCodesConfigSrc {
    pub fn resolve(&self) -> Result<RecoveryCodesConfig, ConfigError> {
        Ok(RecoveryCodesConfig {
            count: self.count.resolve()?,
            code_length: self.code_length.resolve()?,
        })
    }
}

impl Default for RecoveryCodesConfigSrc {
    fn default() -> Self {
        Self {
            count: default_recovery_code_count_or(),
            code_length: default_recovery_code_length_or(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_true_or() -> RefOr<bool> {
    RefOr::Value(true)
}

fn default_argon2_time() -> u32 {
    3
}

fn default_argon2_time_or() -> RefOr<u32> {
    RefOr::Value(3)
}

fn default_argon2_memory() -> u32 {
    65536
}

fn default_argon2_memory_or() -> RefOr<u32> {
    RefOr::Value(65536)
}

fn default_argon2_parallelism() -> u32 {
    2
}

fn default_argon2_parallelism_or() -> RefOr<u32> {
    RefOr::Value(2)
}

fn default_min_length() -> usize {
    12
}

fn default_min_length_or() -> RefOr<usize> {
    RefOr::Value(12)
}

fn default_passkey_timeout() -> u64 {
    60
}

fn default_passkey_timeout_or() -> RefOr<u64> {
    RefOr::Value(60)
}

fn default_totp_period() -> u32 {
    30
}

fn default_totp_period_or() -> RefOr<u32> {
    RefOr::Value(30)
}

fn default_totp_digits() -> u32 {
    6
}

fn default_totp_digits_or() -> RefOr<u32> {
    RefOr::Value(6)
}

fn default_totp_skew() -> u32 {
    1
}

fn default_totp_skew_or() -> RefOr<u32> {
    RefOr::Value(1)
}

fn default_recovery_code_count() -> u32 {
    10
}

fn default_recovery_code_count_or() -> RefOr<u32> {
    RefOr::Value(10)
}

fn default_recovery_code_length() -> u32 {
    12
}

fn default_recovery_code_length_or() -> RefOr<u32> {
    RefOr::Value(12)
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
            rp_id: String::new(),
            rp_name: String::new(),
            origins: Vec::new(),
            user_verification: UserVerification::default(),
            resident_key: ResidentKey::default(),
            timeout_seconds: default_passkey_timeout(),
        }
    }
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            period: default_totp_period(),
            digits: default_totp_digits(),
            algorithm: TotpAlgorithm::default(),
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
