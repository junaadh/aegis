//! Aegis Core - Pure domain layer
//!
//! This crate contains the core domain logic for the Aegis authentication system.

mod identity;
mod ids;
mod traits;

pub use identity::*;
pub use ids::*;
pub use traits::*;
