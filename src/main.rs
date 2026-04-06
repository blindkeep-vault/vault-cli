mod agent;
mod cmd;
mod db;
mod server;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
#[derive(Parser)]
#[command(
    name = "vault-cli",
    about = "BlindKeep vault CLI — download drops, notarize documents, verify certificates"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// API base URL
    #[arg(
        long,
        env = "VAULT_API_URL",
        default_value = "https://api.blindkeep.com",
        global = true
    )]
    api_url: String,

    // Legacy positional args for backwards compat (drop download)
    /// Drop key or mnemonic (legacy usage: vault-cli KEY [KEY2])
    key: Option<String>,
    key2: Option<String>,

    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Download and decrypt a drop (same as legacy positional args)
    Download {
        key: String,
        key2: Option<String>,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Encrypt and upload a file as an anonymous drop
    Drop {
        /// File to encrypt and upload
        file: PathBuf,
    },
    /// Notarize a file or hash
    Notarize {
        /// File to notarize or hex SHA-256 hash
        input: String,
        /// JWT token
        #[arg(long, env = "VAULT_TOKEN")]
        token: String,
        /// Item ID to link
        #[arg(long)]
        item_id: Option<String>,
        /// Output certificate file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Verify a notarization certificate
    Verify {
        /// Certificate JSON file
        certificate: PathBuf,
        /// Optional document to verify hash against
        document: Option<PathBuf>,
    },
    /// List notarizations
    Notarizations {
        /// JWT token
        #[arg(long, env = "VAULT_TOKEN")]
        token: String,
    },
    /// Register a new account
    Register,
    /// Log in with email and password
    Login,
    /// Clear stored session
    Logout,
    /// Manage API keys
    Apikey {
        #[command(subcommand)]
        action: ApikeyAction,
    },
    /// Show current authentication status
    Status,
    /// Store a secret
    Put {
        /// Secret label (e.g., "prod/db-password")
        label: String,
        /// Secret value (omit to read from stdin, prefix with @ for file)
        value: Option<String>,
    },
    /// Retrieve a secret
    Get {
        /// Secret label
        label: String,
        /// Output file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// List secrets
    Ls {
        /// Optional prefix filter
        prefix: Option<String>,
    },
    /// Delete a secret
    Rm {
        /// Secret label
        label: String,
    },
    /// Manage environment files
    Env {
        #[command(subcommand)]
        action: EnvAction,
    },
    /// Share secrets with other users
    Grant {
        #[command(subcommand)]
        action: GrantAction,
    },
    /// Store and retrieve encrypted files
    File {
        #[command(subcommand)]
        action: FileAction,
    },
    /// Manage the key-caching agent daemon
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },
    /// Lock the running agent (zeroize cached key)
    Lock,
    /// Start a self-hosted BlindKeep-compatible API server
    Serve {
        /// Port to listen on
        #[arg(long, default_value = "7890")]
        port: u16,
        /// Host/IP to bind to
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Path to SQLite database file
        #[arg(long)]
        db_path: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub(crate) enum AgentAction {
    /// Start the key-caching agent daemon
    Start {
        /// Inactivity timeout in minutes (default: 30)
        #[arg(long, default_value = "30")]
        timeout: u64,
    },
    /// Stop the running agent daemon
    Stop,
    /// Show agent status
    Status,
}

#[derive(Subcommand)]
pub(crate) enum ApikeyAction {
    /// Create a new API key
    Create {
        /// Name for the API key
        name: String,
        /// Make the key read-only
        #[arg(long)]
        read_only: bool,
        /// Create a scoped key (access only granted items)
        #[arg(long)]
        scoped: bool,
        /// Expiry duration (e.g., "30d", "90d", "1y")
        #[arg(long)]
        expires: Option<String>,
    },
    /// List API keys
    List,
    /// Revoke an API key
    Revoke {
        /// API key ID to revoke
        id: String,
    },
    /// Grant an item to a scoped API key
    Grant {
        /// API key ID
        key_id: String,
        /// Item label to grant
        label: String,
    },
    /// List items granted to an API key
    Grants {
        /// API key ID
        key_id: String,
    },
    /// Revoke an item grant from an API key
    Ungrant {
        /// API key ID
        key_id: String,
        /// Item label to revoke
        label: String,
    },
    /// Rotate an API key (create new, copy grants, revoke old)
    Rotate {
        /// API key ID or prefix to rotate
        key: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum EnvAction {
    /// Store a .env file in the vault
    Push {
        /// Label for this env file (e.g., "myapp/prod")
        label: String,
        /// .env file path (default: .env, use "-" for stdin)
        #[arg(default_value = ".env")]
        file: String,
    },
    /// Retrieve a .env file from the vault
    Pull {
        /// Label of the env file
        label: String,
        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Inject env file variables and run a command
    Run {
        /// Label of the env file
        label: String,
        /// Command and arguments to run
        #[arg(last = true)]
        cmd: Vec<String>,
    },
    /// Print export statements for eval (inject into current shell)
    Export {
        /// Label of the env file
        label: String,
    },
    /// Inject secrets by prefix and run a command
    Inject {
        /// Label prefix to match (e.g., "prod/")
        prefix: String,
        /// Command and arguments to run
        #[arg(last = true)]
        cmd: Vec<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum GrantAction {
    /// Share a secret with another BlindKeep user
    Create {
        /// Secret label to share (e.g., "prod/db-password")
        label: String,
        /// Recipient's email address
        #[arg(long)]
        to: String,
        /// Maximum number of views allowed
        #[arg(long)]
        max_views: Option<u32>,
        /// Expiry duration (e.g., "24h", "7d", "30d", "1y")
        #[arg(long)]
        expires: Option<String>,
        /// Grant read-only access (view only, no download)
        #[arg(long)]
        read_only: bool,
    },
    /// List grants (sent and received)
    List {
        /// Show only grants you sent
        #[arg(long, conflicts_with = "received")]
        sent: bool,
        /// Show only grants you received
        #[arg(long, conflicts_with = "sent")]
        received: bool,
    },
    /// Access a received grant (decrypt and display)
    Access {
        /// Grant ID (UUID)
        id: String,
        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Revoke a grant you sent
    Revoke {
        /// Grant ID (UUID)
        id: String,
    },
    /// Resend email notification for a pending grant
    Resend {
        /// Grant ID (UUID)
        id: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum FileAction {
    /// Store a file in the vault
    Put {
        /// Label (e.g. "contracts/nda.pdf")
        label: String,
        /// Path to the file to encrypt and store
        file: PathBuf,
    },
    /// Retrieve a file from the vault
    Get {
        /// File label
        label: String,
        /// Output path (default: original filename in current directory)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

pub(crate) enum ParsedInput {
    Direct {
        drop_id: String,
        key: [u8; 32],
    },
    Mnemonic {
        mnemonic: String,
        drop_id: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    let client = reqwest::blocking::Client::new();

    match cli.command {
        Some(Command::Download { key, key2, output }) => {
            cmd::drops::run_drop_download(&client, &cli.api_url, &key, key2.as_deref(), output);
        }
        Some(Command::Drop { file }) => {
            cmd::drops::run_drop_upload(&client, &cli.api_url, &file);
        }
        Some(Command::Notarize {
            input,
            token,
            item_id,
            output,
        }) => {
            cmd::notarize::run_notarize(
                &client,
                &cli.api_url,
                &token,
                &input,
                item_id.as_deref(),
                output,
            );
        }
        Some(Command::Verify {
            certificate,
            document,
        }) => {
            cmd::notarize::run_verify(&certificate, document.as_deref());
        }
        Some(Command::Notarizations { token }) => {
            cmd::notarize::run_list_notarizations(&client, &cli.api_url, &token);
        }
        Some(Command::Register) => {
            cmd::auth::run_register(&client, &cli.api_url);
        }
        Some(Command::Login) => {
            cmd::auth::run_login(&client, &cli.api_url);
        }
        Some(Command::Logout) => {
            cmd::auth::run_logout();
        }
        Some(Command::Apikey { action }) => {
            cmd::apikey::run_apikey(&client, &cli.api_url, action);
        }
        Some(Command::Status) => {
            cmd::auth::run_status(&cli.api_url);
        }
        Some(Command::Put { label, value }) => {
            cmd::secrets::run_put(&client, &cli.api_url, &label, value.as_deref());
        }
        Some(Command::Get { label, output }) => {
            cmd::secrets::run_get(&client, &cli.api_url, &label, output);
        }
        Some(Command::Ls { prefix }) => {
            cmd::secrets::run_ls(&client, &cli.api_url, prefix.as_deref());
        }
        Some(Command::Rm { label }) => {
            cmd::secrets::run_rm(&client, &cli.api_url, &label);
        }
        Some(Command::Env { action }) => match action {
            EnvAction::Push { label, file } => {
                cmd::env::run_env_push(&client, &cli.api_url, &label, &file);
            }
            EnvAction::Pull { label, output } => {
                cmd::env::run_env_pull(&client, &cli.api_url, &label, output);
            }
            EnvAction::Run { label, cmd } => {
                cmd::env::run_env_run(&client, &cli.api_url, &label, &cmd);
            }
            EnvAction::Export { label } => {
                cmd::env::run_env_export(&client, &cli.api_url, &label);
            }
            EnvAction::Inject { prefix, cmd } => {
                cmd::env::run_env(&client, &cli.api_url, &prefix, &cmd);
            }
        },
        Some(Command::Grant { action }) => {
            cmd::grants::run_grant(&client, &cli.api_url, action);
        }
        Some(Command::File { action }) => match action {
            FileAction::Put { label, file } => {
                cmd::files::run_file_put(&client, &cli.api_url, &label, &file);
            }
            FileAction::Get { label, output } => {
                cmd::files::run_file_get(&client, &cli.api_url, &label, output);
            }
        },
        Some(Command::Agent { action }) => match action {
            AgentAction::Start { timeout } => agent::run_start(timeout),
            AgentAction::Stop => agent::run_stop(),
            AgentAction::Status => agent::run_status(),
        },
        Some(Command::Lock) => agent::run_lock(),
        Some(Command::Serve {
            port,
            host,
            db_path,
        }) => {
            let db_path = db_path.unwrap_or_else(server::default_db_path);
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(server::run_server(&host, port, db_path));
        }
        None => {
            // Legacy: positional args for drop download
            if let Some(key) = cli.key {
                cmd::drops::run_drop_download(
                    &client,
                    &cli.api_url,
                    &key,
                    cli.key2.as_deref(),
                    cli.output,
                );
            } else {
                eprintln!("Usage: vault-cli <COMMAND> or vault-cli <KEY> [KEY2]");
                eprintln!("  Commands: download, notarize, verify, notarizations");
                std::process::exit(1);
            }
        }
    }
}
