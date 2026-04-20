//! Aegis Types — API request/response DTOs.
//!
//! Standalone types for the Aegis HTTP API. These types do NOT depend on
//! `aegis-core` — all conversions between domain types and API types happen
//! in `aegis-app`.

mod common;
mod error;
mod internal;
mod request;
mod response;

pub use common::*;
pub use error::*;
pub use internal::*;
pub use request::*;
pub use response::*;
