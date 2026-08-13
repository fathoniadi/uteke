//! CLI definition for uteke-web (clap).
//!
//! Binary `uteke-web` with three top-level subcommands:
//! - `serve` — run the axum server
//! - `credential` — manage OAuth2 clients
//! - `user` — manage dashboard users

use clap::{Parser, Subcommand};

/// uteke-web — OAuth2 auth server + reverse proxy + dashboard for uteke-server.
#[derive(Parser, Debug)]
#[command(name = "uteke-web", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run the uteke-web server (axum).
    Serve {
        /// Override bind address (config: web.listen).
        #[arg(long)]
        listen: Option<String>,
        /// Override upstream uteke-server URL (config: web.upstream).
        #[arg(long)]
        upstream: Option<String>,
    },
    /// Manage OAuth2 client credentials.
    Credential {
        #[command(subcommand)]
        action: CredentialAction,
    },
    /// Manage dashboard users.
    User {
        #[command(subcommand)]
        action: UserAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum CredentialAction {
    /// Register a new OAuth2 client.
    Add {
        /// Client ID (must be unique).
        client_id: String,
        /// Client secret (will be bcrypt-hashed before storage).
        client_secret: String,
        /// Redirect URI(s). Repeatable.
        #[arg(long = "redirect-uri", value_name = "URL")]
        redirect_uris: Vec<String>,
    },
    /// Delete a client by its database row ID or client_id.
    Delete { id: String },
    /// List all registered clients.
    List,
}

#[derive(Subcommand, Debug)]
pub enum UserAction {
    /// Create a new dashboard user.
    Add { username: String, password: String },
    /// Delete a user by row ID or username.
    Delete { id: String },
    /// Change a user's password.
    ChangePassword { id: String, new_password: String },
    /// Unlock a locked-out user (reset failed_attempts + locked flag).
    Unlock { id: String },
    /// List all users.
    List,
}
