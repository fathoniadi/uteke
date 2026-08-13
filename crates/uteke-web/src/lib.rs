//! uteke-web library — OAuth2 auth server + reverse proxy + dashboard.
//!
//! The binary entry point lives in `src/main.rs`; this lib re-exports the
//! modules so integration tests can exercise handlers directly.

pub mod app;
pub mod audit;
pub mod auth_store;
pub mod cli;
pub mod config;
pub mod dashboard;
pub mod dashboard_api;
pub mod jwt;
pub mod metrics;
pub mod oauth;
pub mod pkce;
pub mod proxy;
pub mod session;
pub mod state;
