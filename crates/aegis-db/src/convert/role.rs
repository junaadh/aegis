use aegis_core::{
    EffectivePermissions, Permission, Role, RoleId, RoleName, UserId,
    UserRoleAssignment,
};

use crate::row::{RoleRow, UserRoleAssignmentRow};

impl TryFrom<RoleRow> for Role {
    type Error = String;

    fn try_from(row: RoleRow) -> Result<Self, Self::Error> {
        let name = RoleName::parse(&row.name).map_err(|e| e.to_string())?;

        let permissions: Vec<String> = match &row.permissions {
            serde_json::Value::Array(arr) => arr
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
            _ => return Err("permissions must be a json array".to_owned()),
        };

        let parsed: Vec<Permission> =
            permissions.iter().filter_map(|p| p.parse().ok()).collect();

        let effective = EffectivePermissions::new(parsed);

        Role::new(
            RoleId::from_uuid(row.id),
            name,
            row.description,
            effective,
            row.created_at,
            row.updated_at,
        )
        .map_err(|e| e.to_string())
    }
}

impl From<UserRoleAssignmentRow> for UserRoleAssignment {
    fn from(row: UserRoleAssignmentRow) -> Self {
        Self {
            user_id: UserId::from_uuid(row.user_id),
            role_id: RoleId::from_uuid(row.role_id),
            granted_at: row.granted_at,
            expires_at: row.expires_at,
        }
    }
}
