//! uteke-web — OAuth2 auth server + reverse proxy + dashboard for uteke-server.
//!
//! Single axum binary with three roles in one process.

use clap::Parser;

use uteke_web::auth_store::AuthStore;
use uteke_web::cli::{Cli, Commands, CredentialAction, UserAction};
use uteke_web::config::WebConfig;

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Commands::Serve { listen, upstream } => run_serve(listen, upstream),
        Commands::Credential { action } => run_credential(action),
        Commands::User { action } => run_user(action),
    };
    if code != 0 {
        std::process::exit(code);
    }
}

/// Initialize logging: console (stdout) + daily-rotated file (if `log_dir` set).
///
/// Returns a guard that must stay alive for the file writer to keep flushing.
/// Console level follows `RUST_LOG` env or `log_level` config (default: info).
/// File level always captures at the same level as console.
fn init_logging(log_dir: &str, log_level: &str) -> Box<dyn std::any::Any + Send> {
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

    // Console layer (stdout, human-readable).
    let console_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stdout)
        .with_filter(filter.clone());

    // File layer (daily rotation) — only if log_dir is non-empty.
    if log_dir.is_empty() {
        tracing_subscriber::registry().with(console_layer).init();
        // Return a dummy guard — nothing to keep alive.
        Box::new(())
    } else {
        // Ensure log directory exists.
        let _ = std::fs::create_dir_all(log_dir);

        let file_appender = tracing_appender::rolling::daily(log_dir, "uteke-web.log");
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        let file_layer = tracing_subscriber::fmt::layer()
            .with_writer(non_blocking)
            .with_ansi(false) // no color codes in file
            .with_filter(filter);

        tracing_subscriber::registry()
            .with(console_layer)
            .with(file_layer)
            .init();

        Box::new(guard)
    }
}

// ── serve ───────────────────────────────────────────────────────────────────

fn run_serve(cli_listen: Option<String>, cli_upstream: Option<String>) -> i32 {
    let mut config = WebConfig::load();
    config.expand_paths();
    if let Some(l) = cli_listen {
        config.listen = l;
    }
    if let Some(u) = cli_upstream {
        config.upstream = u;
    }

    // Initialize logging (console + daily file rotation if log_dir configured).
    // The guard must stay alive for the entire process lifetime.
    let _log_guard = init_logging(&config.log_dir, &config.log_level);
    if let Err(e) = config.validate() {
        eprintln!("Config error: {e}");
        return 1;
    }

    // Open auth store.
    let store = match AuthStore::open(&config.db_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to open auth store at {}: {e}", config.db_path);
            return 1;
        }
    };

    // Ensure the dashboard OAuth2 client exists (public client, no secret).
    ensure_dashboard_client(&store, &config.issuer);

    let audit = uteke_web::audit::AuditLog::new(&config.audit_log_path);
    let state = uteke_web::state::AppState::new(config.clone(), store, audit);

    // Purge expired sessions, auth codes, refresh tokens, and old login attempts.
    if let Err(e) = state.store.purge_expired_sessions() {
        tracing::warn!("session purge failed: {e}");
    }
    if let Err(e) = state.store.purge_expired() {
        tracing::warn!("expired token purge failed: {e}");
    }

    let app = uteke_web::app::build_app(state.clone());
    let listen = config.listen.clone();

    tracing::info!(
        "uteke-web listening on {} (upstream: {}, issuer: {})",
        config.listen,
        config.upstream,
        config.issuer
    );

    let rt = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to create tokio runtime: {e}");
            return 1;
        }
    };
    rt.block_on(async {
        let listener = match tokio::net::TcpListener::bind(&listen).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Failed to bind {listen}: {e}");
                return;
            }
        };
        // Graceful shutdown on Ctrl-C / SIGTERM.
        let shutdown = async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutdown signal received, stopping...");
        };
        if let Err(e) = axum::serve(listener, app)
            .with_graceful_shutdown(shutdown)
            .await
        {
            tracing::error!("server error: {e}");
        }
    });
    0
}

/// Ensure the dashboard's own public client is registered.
fn ensure_dashboard_client(store: &AuthStore, issuer: &str) {
    if store
        .get_client_by_id(uteke_web::dashboard::DASHBOARD_CLIENT_ID)
        .is_some()
    {
        return;
    }
    let issuer_redirect = format!("{issuer}/dashboard/callback");
    match store.add_client(
        uteke_web::dashboard::DASHBOARD_CLIENT_ID,
        "",
        vec![issuer_redirect],
        vec!["read".to_string(), "write".to_string()],
        true, // public client — no secret
        false,
    ) {
        Ok(_) => tracing::info!("registered dashboard OAuth2 client"),
        Err(e) => tracing::warn!("failed to register dashboard client: {e}"),
    }
}

// ── credential ──────────────────────────────────────────────────────────────

fn run_credential(action: CredentialAction) -> i32 {
    let _log_guard = init_logging("", "warn"); // CLI: stdout only, warn level
    let config = load_config_for_admin();
    let store = match AuthStore::open(&config.db_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to open auth store: {e}");
            return 1;
        }
    };
    match action {
        CredentialAction::Add {
            client_id,
            client_secret,
            redirect_uris,
        } => {
            let scopes = vec!["read".to_string(), "write".to_string()];
            match store.add_client(
                &client_id,
                &client_secret,
                redirect_uris,
                scopes,
                false,
                false,
            ) {
                Ok(c) => {
                    println!(
                        "Added client: id={}, client_id={}, redirect_uris={:?}",
                        c.id, c.client_id, c.redirect_uris
                    );
                    0
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    1
                }
            }
        }
        CredentialAction::Delete { id } => match store.delete_client(&id) {
            Ok(n) => {
                println!("Deleted {n} client(s)");
                0
            }
            Err(e) => {
                eprintln!("Error: {e}");
                1
            }
        },
        CredentialAction::List => match store.list_clients() {
            Ok(clients) => {
                if clients.is_empty() {
                    println!("No clients registered.");
                }
                for c in clients {
                    println!(
                        "id={} client_id={} public={} dynamic={} redirect_uris={:?} scopes={:?}",
                        c.id, c.client_id, c.public, c.dynamic, c.redirect_uris, c.scopes
                    );
                }
                0
            }
            Err(e) => {
                eprintln!("Error: {e}");
                1
            }
        },
    }
}

// ── user ────────────────────────────────────────────────────────────────────

fn run_user(action: UserAction) -> i32 {
    let _log_guard = init_logging("", "warn"); // CLI: stdout only, warn level
    let config = load_config_for_admin();
    let store = match AuthStore::open(&config.db_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to open auth store: {e}");
            return 1;
        }
    };
    match action {
        UserAction::Add { username, password } => match store.add_user(&username, &password) {
            Ok(u) => {
                println!("Added user: id={}, username={}", u.id, u.username);
                0
            }
            Err(e) => {
                eprintln!("Error: {e}");
                1
            }
        },
        UserAction::Delete { id } => match store.delete_user(&id) {
            Ok(n) => {
                println!("Deleted {n} user(s)");
                0
            }
            Err(e) => {
                eprintln!("Error: {e}");
                1
            }
        },
        UserAction::ChangePassword { id, new_password } => {
            match store.change_password(&id, &new_password) {
                Ok(_) => {
                    println!("Password changed for {id}");
                    0
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    1
                }
            }
        }
        UserAction::Unlock { id } => match store.unlock_user(&id) {
            Ok(_) => {
                println!("Unlocked {id}");
                0
            }
            Err(e) => {
                eprintln!("Error: {e}");
                1
            }
        },
        UserAction::List => match store.list_users() {
            Ok(users) => {
                if users.is_empty() {
                    println!("No users.");
                }
                for u in users {
                    println!(
                        "id={} username={} locked={} failed_attempts={} created_at={}",
                        u.id, u.username, u.locked, u.failed_attempts, u.created_at
                    );
                }
                0
            }
            Err(e) => {
                eprintln!("Error: {e}");
                1
            }
        },
    }
}

/// Load config for admin CLI commands (paths expanded, no validation of secrets).
fn load_config_for_admin() -> WebConfig {
    let mut config = WebConfig::load();
    config.expand_paths();
    config
}
