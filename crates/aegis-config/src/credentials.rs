use crate::enums::{HashingAlgorithm, ResidentKey, TotpAlgorithm, UserVerification};
use crate::error::ConfigError;
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

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CredentialsConfigSrc {
    #[serde(default)]
    pub password: PasswordConfigSrc,
    #[serde(default)]
    pub passkeys: PasskeysConfigSrc,
    #[serde(default)]
    pub mfa: MfaConfigSrc,
}

impl CredentialsConfigSrc {
    pub fn resolve(&self) -> Result<CredentialsConfig, ConfigError> {
        Ok(CredentialsConfig {
            password: self.password.resolve()?,
            passkeys: self.passkeys.resolve()?,
            mfa: self.mfa.resolve()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PasswordConfigSrc {
    #[schemars(title = "Hashing algorithm", description = "Password hashing algorithm.")]
    #[serde(default)]
    pub hashing_algorithm: HashingAlgorithm,

    #[serde(default)]
    pub argon2: Argon2ConfigSrc,

    #[serde(default)]
    pub policy: PasswordPolicyConfigSrc,
}

impl PasswordConfigSrc {
    pub fn resolve(&self) -> Result<PasswordConfig, ConfigError> {
        Ok(PasswordConfig {
            hashing_algorithm: self.hashing_algorithm,
            argon2: self.argon2.resolve()?,
            policy: self.policy.resolve()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Argon2ConfigSrc {
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

impl Argon2ConfigSrc {
    pub fn resolve(&self) -> Result<Argon2Config, ConfigError> {
        Ok(Argon2Config {
            time_cost: self.time_cost,
            memory_cost: self.memory_cost,
            parallelism: self.parallelism,
        })
    }
}

impl Default for Argon2ConfigSrc {
    fn default() -> Self {
        Self {
            time_cost: default_argon2_time(),
            memory_cost: default_argon2_memory(),
            parallelism: default_argon2_parallelism(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PasswordPolicyConfigSrc {
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

impl PasswordPolicyConfigSrc {
    pub fn resolve(&self) -> Result<PasswordPolicyConfig, ConfigError> {
        Ok(PasswordPolicyConfig {
            min_length: self.min_length,
            require_uppercase: self.require_uppercase,
            require_lowercase: self.require_lowercase,
            require_digit: self.require_digit,
            require_symbol: self.require_symbol,
            disallow_common: self.disallow_common,
        })
    }
}

impl Default for PasswordPolicyConfigSrc {
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PasskeysConfigSrc {
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

impl PasskeysConfigSrc {
    pub fn resolve(&self) -> Result<PasskeysConfig, ConfigError> {
        Ok(PasskeysConfig {
            rp_id: self.rp_id.clone(),
            rp_name: self.rp_name.clone(),
            origins: self.origins.clone(),
            user_verification: self.user_verification,
            resident_key: self.resident_key,
            timeout_seconds: self.timeout_seconds,
        })
    }
}

impl Default for PasskeysConfigSrc {
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

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MfaConfigSrc {
    #[serde(default)]
    pub totp: TotpConfigSrc,
}

impl MfaConfigSrc {
    pub fn resolve(&self) -> Result<MfaConfig, ConfigError> {
        Ok(MfaConfig {
            totp: self.totp.resolve()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TotpConfigSrc {
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
    pub recovery_codes: RecoveryCodesConfigSrc,
}

impl TotpConfigSrc {
    pub fn resolve(&self) -> Result<TotpConfig, ConfigError> {
        Ok(TotpConfig {
            issuer: self.issuer.clone(),
            period: self.period,
            digits: self.digits,
            algorithm: self.algorithm,
            skew: self.skew,
            recovery_codes: self.recovery_codes.resolve()?,
        })
    }
}

impl Default for TotpConfigSrc {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            period: default_totp_period(),
            digits: default_totp_digits(),
            algorithm: TotpAlgorithm::default(),
            skew: default_totp_skew(),
            recovery_codes: RecoveryCodesConfigSrc::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCodesConfigSrc {
    #[schemars(title = "Count", description = "Number of recovery codes to generate.")]
    #[serde(default = "default_recovery_code_count")]
    pub count: u32,

    #[schemars(title = "Code length", description = "Length of each recovery code.")]
    #[serde(default = "default_recovery_code_length")]
    pub code_length: u32,
}

impl RecoveryCodesConfigSrc {
    pub fn resolve(&self) -> Result<RecoveryCodesConfig, ConfigError> {
        Ok(RecoveryCodesConfig {
            count: self.count,
            code_length: self.code_length,
        })
    }
}

impl Default for RecoveryCodesConfigSrc {
    fn default() -> Self {
        Self {
            count: default_recovery_code_count(),
            code_length: default_recovery_code_length(),
        }
    }
}

fn default_true() -> bool {
    true
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

fn default_passkey_timeout() -> u64 {
    60
}

fn default_totp_period() -> u32 {
    30
}

fn default_totp_digits() -> u32 {
    6
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
