//! Aegis DB — Database row types and conversions.
//!
//! Row structs map 1:1 to PostgreSQL tables using `sqlx::FromRow`.
//! Conversions between row types and domain types live in the `convert` module.

pub mod convert;
pub mod error;
pub mod repo;
pub mod row;
