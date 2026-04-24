use std::str::FromStr;

use aegis_core::{
    Actor, ActorType, AuditEntry, AuditTarget, GuestId, Metadata, UserId,
};

use crate::error::ConversionError;
use crate::row::AuditLogRow;

impl TryFrom<AuditLogRow> for AuditEntry {
    type Error = ConversionError;

    fn try_from(row: AuditLogRow) -> Result<Self, Self::Error> {
        let actor_type =
            ActorType::from_str(&row.actor_type).map_err(|_| {
                ConversionError::InvalidActorType(row.actor_type.clone())
            })?;

        let actor = match actor_type {
            ActorType::User => {
                Actor::User(UserId::from_uuid(row.actor_id.unwrap_or_default()))
            }
            ActorType::Guest => Actor::Guest(GuestId::from_uuid(
                row.actor_id.unwrap_or_default(),
            )),
            ActorType::Service => Actor::Service(
                row.actor_id.map(|id| id.to_string()).unwrap_or_default(),
            ),
            ActorType::System => Actor::System,
        };

        let target = row.target_type.map(|target_type| AuditTarget {
            target_type,
            target_id: row.target_id,
        });

        let metadata = Metadata::new(
            serde_json::to_string(&row.metadata).unwrap_or_default(),
        );

        Ok(Self {
            id: row.id,
            event_type: row.event_type,
            actor,
            target,
            ip_address: row.ip_address,
            user_agent: row.user_agent,
            request_id: row.request_id,
            metadata,
            created_at: row.created_at,
        })
    }
}
