use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct ComplianceConfig {
    #[serde(default)]
    pub data_retention: DataRetentionConfig,
    #[serde(default)]
    pub deletion: DeletionConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DataRetentionConfig {
    #[serde(default = "default_audit_log_days")]
    pub audit_log_days: u32,
    #[serde(default = "default_guest_ttl_days")]
    pub guest_ttl_days: u32,
    #[serde(default = "default_anonymize_after_days")]
    pub deleted_user_anonymize_after_days: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeletionConfig {
    #[serde(default = "default_anonymize_pattern")]
    pub anonymize_email_pattern: String,
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
