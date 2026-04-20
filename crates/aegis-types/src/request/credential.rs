use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordChangeRequest {
    pub current_password: String,
    pub new_password: String,
}
