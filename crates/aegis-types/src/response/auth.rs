use serde::{Deserialize, Serialize};

use super::identity::IdentityResponse;
use super::session::SessionInfo;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthResponse {
    pub identity: IdentityResponse,
    pub session: SessionInfo,
}
