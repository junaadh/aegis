use aegis_core::{User, UserStatus};

use crate::dto::UserLookupResult;

pub fn user_to_lookup_result(
    user: &User,
    roles: Option<Vec<String>>,
) -> UserLookupResult {
    UserLookupResult {
        id: user.id.as_uuid(),
        email: Some(user.email.as_str().to_owned()),
        display_name: Some(user.display_name.as_str().to_owned()),
        status: match user.status {
            UserStatus::Active => "active".to_owned(),
            UserStatus::Disabled => "disabled".to_owned(),
            UserStatus::PendingVerification => {
                "pending_verification".to_owned()
            }
            UserStatus::Deleted => "deleted".to_owned(),
        },
        email_verified: Some(user.is_email_verified()),
        roles,
        metadata: Some(user.metadata.as_str().to_owned()),
    }
}
