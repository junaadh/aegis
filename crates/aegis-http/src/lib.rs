#![allow(clippy::type_complexity)]

mod auth;
mod context;
mod cookies;
mod error;
mod handlers;
mod mapping;
mod middleware;
mod router;
mod state;

pub use error::HttpError;
pub use middleware::{
    auth_context_middleware, internal_auth_middleware, internal_network_guard,
    request_id_middleware,
};
pub use router::app_router;
pub use state::{AppHandle, AppState};
