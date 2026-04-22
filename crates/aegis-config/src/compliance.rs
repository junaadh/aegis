use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct ComplianceConfig {
    #[serde(default)]
    pub data_retention: DataRetentionConfig,

    #[serde(default)]
    pub deletion: DeletionConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DataRetentionConfig {
    #[schemars(title = "Audit log retention", description = "Days to retain audit logs (~7 years = 2555).")]
    #[serde(default = "default_audit_log_days")]
    pub audit_log_days: u32,

    #[schemars(title = "Guest TTL", description = "Days before expired guests are purged.")]
    #[serde(default = "default_guest_ttl_days")]
    pub guest_ttl_days: u32,

    #[schemars(title = "Anonymize after", description = "Days after deletion to anonymize user data (0 = immediate).")]
    #[serde(default = "default_anonymize_after_days")]
    pub deleted_user_anonymize_after_days: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeletionConfig {
    #[schemars(title = "Anonymize pattern", description = "Pattern for anonymized emails. Use {hash} as placeholder.")]
    #[serde(default = "default_anonymize_pattern")]
    pub anonymize_email_pattern: String,

    #[schemars(title = "Preserve referential integrity", description = "Keep anonymized records for referential integrity.")]
    #[serde(default = "default_true")]
    pub preserve_referential_integrity: bool,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ComplianceConfigSrc {
    #[serde(default)]
    pub data_retention: DataRetentionConfigSrc,

    #[serde(default)]
    pub deletion: DeletionConfigSrc,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DataRetentionConfigSrc {
    #[schemars(title = "Audit log retention", description = "Days to retain audit logs (~7 years = 2555).")]
    #[serde(default = "default_audit_log_days")]
    pub audit_log_days: u32,

    #[schemars(title = "Guest TTL", description = "Days before expired guests are purged.")]
    #[serde(default = "default_guest_ttl_days")]
    pub guest_ttl_days: u32,

    #[schemars(title = "Anonymize after", description = "Days after deletion to anonymize user data (0 = immediate).")]
    #[serde(default = "default_anonymize_after_days")]
    pub deleted_user_anonymize_after_days: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeletionConfigSrc {
    #[schemars(title = "Anonymize pattern", description = "Pattern for anonymized emails. Use {hash} as placeholder.")]
    #[serde(default = "default_anonymize_pattern")]
    pub anonymize_email_pattern: String,

    #[schemars(title = "Preserve referential integrity", description = "Keep anonymized records for referential integrity.")]
    #[serde(default = "default_true")]
    pub preserve_referential_integrity: bool,
}

fn default_true() -> bool {
    true
}

fn default_audit_log_days() -> u32 {
    2555
}

fn default_guest_ttl_days() -> u32 {
    30
}

fn default_anonymize_after_days() -> u32 {
    0
}

fn default_anonymize_pattern() -> String {
    "deleted-{hash}@anonymized.local".to_owned()
}

impl Default for DataRetentionConfig {
    fn default() -> Self {
        Self {
            audit_log_days: default_audit_log_days(),
            guest_ttl_days: default_guest_ttl_days(),
            deleted_user_anonymize_after_days: default_anonymize_after_days(),
        }
    }
}

impl Default for DeletionConfig {
    fn default() -> Self {
        Self {
            anonymize_email_pattern: default_anonymize_pattern(),
            preserve_referential_integrity: default_true(),
        }
    }
}

impl Default for DataRetentionConfigSrc {
    fn default() -> Self {
        Self {
            audit_log_days: default_audit_log_days(),
            guest_ttl_days: default_guest_ttl_days(),
            deleted_user_anonymize_after_days: default_anonymize_after_days(),
        }
    }
}

impl Default for DeletionConfigSrc {
    fn default() -> Self {
        Self {
            anonymize_email_pattern: default_anonymize_pattern(),
            preserve_referential_integrity: default_true(),
        }
    }
}

impl ComplianceConfigSrc {
    pub fn resolve(&self) -> Result<ComplianceConfig, ConfigError> {
        Ok(ComplianceConfig {
            data_retention: self.data_retention.resolve()?,
            deletion: self.deletion.resolve()?,
        })
    }
}

impl DataRetentionConfigSrc {
    pub fn resolve(&self) -> Result<DataRetentionConfig, ConfigError> {
        Ok(DataRetentionConfig {
            audit_log_days: self.audit_log_days,
            guest_ttl_days: self.guest_ttl_days,
            deleted_user_anonymize_after_days: self.deleted_user_anonymize_after_days,
        })
    }
}

impl DeletionConfigSrc {
    pub fn resolve(&self) -> Result<DeletionConfig, ConfigError> {
        Ok(DeletionConfig {
            anonymize_email_pattern: self.anonymize_email_pattern.clone(),
            preserve_referential_integrity: self.preserve_referential_integrity,
        })
    }
}
