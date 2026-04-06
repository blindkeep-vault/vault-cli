mod agent;
mod db;
mod server;

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use clap::{Parser, Subcommand};
use hkdf::Hkdf;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};
use std::io::{Read as IoRead, Write};
use std::path::PathBuf;
use vault_core::crypto::{
    decrypt_item, decrypt_private_key, derive_api_key_keys, derive_master_key, derive_subkey,
    encrypt_item, generate_x25519_keypair, unwrap_grant_key, unwrap_key, unwrap_master_key,
    wrap_key_for_grant, wrap_key_for_recipient, wrap_master_key, MasterKey,
};

#[derive(Parser)]
#[command(
    name = "vault-cli",
    about = "BlindKeep vault CLI — download drops, notarize documents, verify certificates"
)]
struct Cli {
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
enum Command {
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
enum AgentAction {
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
enum ApikeyAction {
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
enum EnvAction {
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
enum GrantAction {
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
enum FileAction {
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

enum ParsedInput {
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
            run_drop_download(&client, &cli.api_url, &key, key2.as_deref(), output);
        }
        Some(Command::Drop { file }) => {
            run_drop_upload(&client, &cli.api_url, &file);
        }
        Some(Command::Notarize {
            input,
            token,
            item_id,
            output,
        }) => {
            run_notarize(
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
            run_verify(&certificate, document.as_deref());
        }
        Some(Command::Notarizations { token }) => {
            run_list_notarizations(&client, &cli.api_url, &token);
        }
        Some(Command::Register) => {
            run_register(&client, &cli.api_url);
        }
        Some(Command::Login) => {
            run_login(&client, &cli.api_url);
        }
        Some(Command::Logout) => {
            run_logout();
        }
        Some(Command::Apikey { action }) => {
            run_apikey(&client, &cli.api_url, action);
        }
        Some(Command::Status) => {
            run_status(&cli.api_url);
        }
        Some(Command::Put { label, value }) => {
            run_put(&client, &cli.api_url, &label, value.as_deref());
        }
        Some(Command::Get { label, output }) => {
            run_get(&client, &cli.api_url, &label, output);
        }
        Some(Command::Ls { prefix }) => {
            run_ls(&client, &cli.api_url, prefix.as_deref());
        }
        Some(Command::Rm { label }) => {
            run_rm(&client, &cli.api_url, &label);
        }
        Some(Command::Env { action }) => match action {
            EnvAction::Push { label, file } => {
                run_env_push(&client, &cli.api_url, &label, &file);
            }
            EnvAction::Pull { label, output } => {
                run_env_pull(&client, &cli.api_url, &label, output);
            }
            EnvAction::Run { label, cmd } => {
                run_env_run(&client, &cli.api_url, &label, &cmd);
            }
            EnvAction::Export { label } => {
                run_env_export(&client, &cli.api_url, &label);
            }
            EnvAction::Inject { prefix, cmd } => {
                run_env(&client, &cli.api_url, &prefix, &cmd);
            }
        },
        Some(Command::Grant { action }) => {
            run_grant(&client, &cli.api_url, action);
        }
        Some(Command::File { action }) => match action {
            FileAction::Put { label, file } => {
                run_file_put(&client, &cli.api_url, &label, &file);
            }
            FileAction::Get { label, output } => {
                run_file_get(&client, &cli.api_url, &label, output);
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
                run_drop_download(&client, &cli.api_url, &key, cli.key2.as_deref(), cli.output);
            } else {
                eprintln!("Usage: vault-cli <COMMAND> or vault-cli <KEY> [KEY2]");
                eprintln!("  Commands: download, notarize, verify, notarizations");
                std::process::exit(1);
            }
        }
    }
}

// --- Session management ---

#[derive(serde::Serialize, serde::Deserialize)]
struct Session {
    api_url: String,
    jwt: String,
    email: String,
    user_id: String,
    client_salt: Vec<u8>,
}

fn session_dir() -> PathBuf {
    dirs::home_dir()
        .expect("cannot determine home directory")
        .join(".vault")
}

fn session_path() -> PathBuf {
    session_dir().join("session.json")
}

fn load_session() -> Option<Session> {
    let data = std::fs::read_to_string(session_path()).ok()?;
    serde_json::from_str(&data).ok()
}

fn save_session(session: &Session) {
    let dir = session_dir();
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| {
        eprintln!("error creating {}: {}", dir.display(), e);
        std::process::exit(1);
    });
    // Set restrictive permissions on session directory
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    let json = serde_json::to_string_pretty(session).expect("serialize session");
    let path = session_path();
    std::fs::write(&path, &json).unwrap_or_else(|e| {
        eprintln!("error writing {}: {}", path.display(), e);
        std::process::exit(1);
    });
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
}

fn clear_session() {
    let _ = std::fs::remove_file(session_path());
}

/// Authentication context for commands that need crypto access.
enum AuthContext {
    /// Full-access: has the user's master key, can decrypt all items.
    Full {
        jwt: String,
        master_key: MasterKey,
        api_url: String,
    },
    /// Scoped: has the API key's own X25519 private key, can only decrypt granted items.
    Scoped {
        jwt: String,
        api_privkey: [u8; 32],
        api_key_id: String,
        api_url: String,
    },
}

impl AuthContext {
    fn jwt(&self) -> &str {
        match self {
            AuthContext::Full { jwt, .. } => jwt,
            AuthContext::Scoped { jwt, .. } => jwt,
        }
    }

    fn api_url(&self) -> &str {
        match self {
            AuthContext::Full { api_url, .. } => api_url,
            AuthContext::Scoped { api_url, .. } => api_url,
        }
    }
}

fn prompt_password(prompt: &str) -> String {
    rpassword::prompt_password(prompt).unwrap_or_else(|e| {
        eprintln!("error reading password: {}", e);
        std::process::exit(1);
    })
}

fn prompt_line(prompt: &str) -> String {
    eprint!("{}", prompt);
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap_or_else(|e| {
        eprintln!("error reading input: {}", e);
        std::process::exit(1);
    });
    line.trim().to_string()
}

fn get_auth(client: &reqwest::blocking::Client, api_url: &str) -> AuthContext {
    // Priority 1: VAULT_API_KEY env var
    if let Ok(api_key) = std::env::var("VAULT_API_KEY") {
        return auth_with_api_key(client, api_url, &api_key);
    }
    // Priority 2: Running agent with cached key
    if let Some((jwt, master_key, _cached_url, _user_id)) = agent::try_retrieve() {
        eprintln!("(using cached credentials from agent)");
        return AuthContext::Full {
            jwt,
            master_key,
            api_url: api_url.to_string(),
        };
    }
    // Priority 3: Session file + password prompt
    if let Some(session) = load_session() {
        let password = prompt_password("Password: ");
        let password_key = derive_master_key(password.as_bytes(), &session.client_salt)
            .unwrap_or_else(|e| {
                eprintln!("error deriving key: {}", e);
                std::process::exit(1);
            });

        // Derive key-wrapping key and unwrap the actual master key
        let master_key = unwrap_master_key_from_profile(client, &session, &password_key);

        // Store in agent if one is running
        agent::try_store(
            &session.jwt,
            &master_key,
            &session.api_url,
            &session.user_id,
        );

        return AuthContext::Full {
            jwt: session.jwt,
            master_key,
            api_url: session.api_url,
        };
    }
    eprintln!("error: not logged in. Run `vault-cli login` or set VAULT_API_KEY");
    std::process::exit(1);
}

fn unwrap_master_key_from_profile(
    client: &reqwest::blocking::Client,
    session: &Session,
    password_key: &MasterKey,
) -> MasterKey {
    let me_resp = client
        .get(format!("{}/auth/me", session.api_url))
        .header("Authorization", format!("Bearer {}", session.jwt))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error fetching profile: {}", e);
            std::process::exit(1);
        });

    if !me_resp.status().is_success() {
        eprintln!("error: session expired, please login again");
        std::process::exit(1);
    }

    let me: serde_json::Value = me_resp.json().expect("invalid JSON");
    let encrypted_master_key = json_to_bytes(&me["encrypted_master_key"]);

    if encrypted_master_key.is_empty() {
        // Legacy account without encrypted_master_key — password_key IS the master key
        return MasterKey::from_bytes(*password_key.as_bytes());
    }

    // Derive key-wrapping key from password_key
    let kwk = derive_subkey(password_key, b"vault-enc").unwrap_or_else(|e| {
        eprintln!("error deriving key-wrapping key: {}", e);
        std::process::exit(1);
    });

    // Two possible concat formats:
    // V1: 0x01 + nonce(24) + ciphertext (ciphertext starts with 0x01 from encrypt_v1)
    // V0: nonce(24) + ciphertext (registration-time, before user_id was known)
    let aad = format!("master:{}", session.user_id);

    if encrypted_master_key.len() < 25 {
        eprintln!("error: encrypted_master_key too short");
        std::process::exit(1);
    }

    // Try V1 first (0x01 + nonce(24) + ciphertext), fall back to V0 (nonce(24) + ciphertext)
    let result = if encrypted_master_key[0] == 0x01 && encrypted_master_key.len() > 25 {
        vault_core::crypto::decrypt_item_auto(
            &kwk,
            &encrypted_master_key[25..],
            &encrypted_master_key[1..25],
            aad.as_bytes(),
        )
        .or_else(|_| {
            // Nonce happened to start with 0x01 — treat as V0
            decrypt_item(
                &kwk,
                &encrypted_master_key[24..],
                &encrypted_master_key[..24],
            )
        })
    } else {
        decrypt_item(
            &kwk,
            &encrypted_master_key[24..],
            &encrypted_master_key[..24],
        )
    }
    .unwrap_or_else(|e| {
        eprintln!("error unwrapping master key: {}", e);
        std::process::exit(1);
    });

    if result.len() != 32 {
        eprintln!("error: invalid master key length");
        std::process::exit(1);
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    MasterKey::from_bytes(bytes)
}

fn parse_api_key(raw_key: &str) -> (String, [u8; 32]) {
    let parts: Vec<&str> = raw_key.splitn(3, '_').collect();
    if parts.len() != 3 || parts[0] != "vk" {
        eprintln!("error: invalid API key format (expected vk_PREFIX_SECRET)");
        std::process::exit(1);
    }
    let prefix = format!("vk_{}", parts[1]);
    let secret_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap_or_else(|e| {
        eprintln!("error: invalid API key secret encoding: {}", e);
        std::process::exit(1);
    });
    if secret_bytes.len() != 32 {
        eprintln!("error: API key secret must be 32 bytes");
        std::process::exit(1);
    }
    (prefix, secret_bytes.try_into().unwrap())
}

fn json_to_bytes(val: &serde_json::Value) -> Vec<u8> {
    match val.as_array() {
        Some(a) => a.iter().map(|v| v.as_u64().unwrap_or(0) as u8).collect(),
        None => Vec::new(),
    }
}

fn auth_with_api_key(
    client: &reqwest::blocking::Client,
    api_url: &str,
    raw_key: &str,
) -> AuthContext {
    let (prefix, secret) = parse_api_key(raw_key);

    let (wrapping_key, auth_key) = derive_api_key_keys(&secret).unwrap_or_else(|e| {
        eprintln!("error deriving API key keys: {}", e);
        std::process::exit(1);
    });

    let resp = client
        .post(format!("{}/auth/api-key", api_url))
        .json(&serde_json::json!({
            "key_prefix": prefix,
            "auth_key": hex::encode(auth_key),
        }))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: API key auth request failed: {}", e);
            std::process::exit(1);
        });

    if !resp.status().is_success() {
        let text = resp.text().unwrap_or_default();
        eprintln!("error: API key authentication failed: {}", text);
        std::process::exit(1);
    }

    let body: serde_json::Value = resp.json().expect("invalid JSON response");
    let jwt = body["token"].as_str().expect("missing token").to_string();
    let api_key_id = body["api_key_id"].as_str().unwrap_or("").to_string();

    // Check if this is a scoped key (has public_key, no wrapped_master_key)
    let has_public_key = body["public_key"].as_array().is_some();
    let has_wrapped_master_key = body["wrapped_master_key"].as_array().is_some();

    if has_public_key && !has_wrapped_master_key {
        // Scoped key: unwrap the API key's own private key
        let encrypted_private_key = json_to_bytes(&body["encrypted_private_key"]);
        let api_privkey_mk = unwrap_master_key(&wrapping_key, &encrypted_private_key)
            .unwrap_or_else(|e| {
                eprintln!("error: failed to unwrap API key private key: {}", e);
                std::process::exit(1);
            });
        let mut api_privkey = [0u8; 32];
        api_privkey.copy_from_slice(api_privkey_mk.as_bytes());

        AuthContext::Scoped {
            jwt,
            api_privkey,
            api_key_id,
            api_url: api_url.to_string(),
        }
    } else {
        // Full-access key: unwrap master key
        let wrapped_master_key = json_to_bytes(&body["wrapped_master_key"]);
        let master_key =
            unwrap_master_key(&wrapping_key, &wrapped_master_key).unwrap_or_else(|e| {
                eprintln!("error: failed to unwrap master key: {}", e);
                std::process::exit(1);
            });

        AuthContext::Full {
            jwt,
            master_key,
            api_url: api_url.to_string(),
        }
    }
}

// --- Login / Logout ---

fn run_register(client: &reqwest::blocking::Client, api_url: &str) {
    let email = prompt_line("Email: ");
    let password = prompt_password("Password: ");
    let password2 = prompt_password("Confirm password: ");

    if password != password2 {
        eprintln!("error: passwords do not match");
        std::process::exit(1);
    }

    if password.len() < 12 {
        eprintln!("error: password must be at least 12 characters");
        std::process::exit(1);
    }

    // Generate client_salt
    let mut client_salt = vec![0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut client_salt);

    eprintln!("Deriving keys...");
    let master_key = derive_master_key(password.as_bytes(), &client_salt).unwrap_or_else(|e| {
        eprintln!("error: key derivation failed: {}", e);
        std::process::exit(1);
    });

    let auth_key = derive_subkey(&master_key, b"vault-auth").unwrap_or_else(|e| {
        eprintln!("error: subkey derivation failed: {}", e);
        std::process::exit(1);
    });

    let enc_key = derive_subkey(&master_key, b"vault-enc").unwrap_or_else(|e| {
        eprintln!("error: subkey derivation failed: {}", e);
        std::process::exit(1);
    });

    // Generate X25519 keypair and encrypt private key
    let (privkey, pubkey) = generate_x25519_keypair();
    let enc_privkey = encrypt_item(&enc_key, &privkey).unwrap_or_else(|e| {
        eprintln!("error encrypting private key: {}", e);
        std::process::exit(1);
    });
    let mut encrypted_private_key = Vec::with_capacity(24 + enc_privkey.ciphertext.len());
    encrypted_private_key.extend_from_slice(&enc_privkey.nonce);
    encrypted_private_key.extend_from_slice(&enc_privkey.ciphertext);

    eprintln!("Registering...");
    let resp = client
        .post(format!("{}/auth/register", api_url))
        .json(&serde_json::json!({
            "email": email,
            "auth_key": hex::encode(auth_key),
            "public_key": pubkey.to_vec(),
            "encrypted_private_key": encrypted_private_key,
            "client_salt": client_salt,
        }))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

    if !resp.status().is_success() {
        let text = resp.text().unwrap_or_default();
        eprintln!("error: registration failed: {}", text);
        std::process::exit(1);
    }

    let auth: serde_json::Value = resp.json().expect("invalid JSON");
    let jwt = auth["token"].as_str().expect("missing token").to_string();
    let user_id = auth["user_id"]
        .as_str()
        .expect("missing user_id")
        .to_string();

    save_session(&Session {
        api_url: api_url.to_string(),
        jwt,
        email: email.clone(),
        user_id,
        client_salt,
    });

    eprintln!("Registered and logged in as {}", email);
}

fn run_login(client: &reqwest::blocking::Client, api_url: &str) {
    let email = prompt_line("Email: ");

    // Get client_salt
    let params_resp = client
        .post(format!("{}/auth/client-params", api_url))
        .json(&serde_json::json!({"email": email}))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

    if !params_resp.status().is_success() {
        eprintln!("error: failed to get client params");
        std::process::exit(1);
    }

    let params: serde_json::Value = params_resp.json().expect("invalid JSON");
    let client_salt: Vec<u8> = params["client_salt"]
        .as_array()
        .expect("missing client_salt")
        .iter()
        .map(|v| v.as_u64().unwrap() as u8)
        .collect();

    let password = prompt_password("Password: ");

    eprintln!("Deriving keys...");
    let password_key = derive_master_key(password.as_bytes(), &client_salt).unwrap_or_else(|e| {
        eprintln!("error: key derivation failed: {}", e);
        std::process::exit(1);
    });

    let auth_key = derive_subkey(&password_key, b"vault-auth").unwrap_or_else(|e| {
        eprintln!("error: subkey derivation failed: {}", e);
        std::process::exit(1);
    });

    let login_resp = client
        .post(format!("{}/auth/login", api_url))
        .json(&serde_json::json!({
            "email": email,
            "auth_key": hex::encode(auth_key),
        }))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

    if !login_resp.status().is_success() {
        let text = login_resp.text().unwrap_or_default();
        eprintln!("error: login failed: {}", text);
        std::process::exit(1);
    }

    let auth: serde_json::Value = login_resp.json().expect("invalid JSON");
    let jwt = auth["token"].as_str().expect("missing token").to_string();
    let user_id = auth["user_id"]
        .as_str()
        .expect("missing user_id")
        .to_string();

    let session = Session {
        api_url: api_url.to_string(),
        jwt,
        email: email.clone(),
        user_id,
        client_salt,
    };

    save_session(&session);

    // Start agent (if not already running) and cache credentials so
    // subsequent commands don't re-prompt for the password — like sudo.
    agent::run_start_quiet(30);
    let master_key = unwrap_master_key_from_profile(client, &session, &password_key);
    agent::try_store(
        &session.jwt,
        &master_key,
        &session.api_url,
        &session.user_id,
    );

    eprintln!("Logged in as {}", email);
}

fn run_logout() {
    clear_session();
    eprintln!("Logged out.");
}

fn run_status(api_url: &str) {
    if std::env::var("VAULT_API_KEY").is_ok() {
        eprintln!("Auth: VAULT_API_KEY environment variable set");
    } else {
        match load_session() {
            Some(session) => {
                eprintln!("Auth: session ({})", session.email);
                eprintln!("API:  {}", session.api_url);
            }
            None => {
                eprintln!("Auth: not logged in");
                eprintln!("API:  {}", api_url);
            }
        }
    }
    agent::run_status();
}

// --- API Key management ---

fn run_apikey(client: &reqwest::blocking::Client, api_url: &str, action: ApikeyAction) {
    match action {
        ApikeyAction::Create {
            name,
            read_only,
            scoped,
            expires,
        } => run_apikey_create(
            client,
            api_url,
            &name,
            read_only,
            scoped,
            expires.as_deref(),
        ),
        ApikeyAction::List => run_apikey_list(client, api_url),
        ApikeyAction::Revoke { id } => run_apikey_revoke(client, api_url, &id),
        ApikeyAction::Grant { key_id, label } => run_apikey_grant(client, api_url, &key_id, &label),
        ApikeyAction::Grants { key_id } => run_apikey_grants(client, api_url, &key_id),
        ApikeyAction::Ungrant { key_id, label } => {
            run_apikey_ungrant(client, api_url, &key_id, &label)
        }
        ApikeyAction::Rotate { key } => run_apikey_rotate(client, api_url, &key),
    }
}

fn run_apikey_create(
    client: &reqwest::blocking::Client,
    api_url: &str,
    name: &str,
    read_only: bool,
    scoped: bool,
    expires: Option<&str>,
) {
    let session = load_session().unwrap_or_else(|| {
        eprintln!("error: not logged in. Run `vault-cli login` first");
        std::process::exit(1);
    });

    // Generate random 32-byte API key secret
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);

    let (wrapping_key, auth_key) = derive_api_key_keys(&secret).unwrap_or_else(|e| {
        eprintln!("error: {}", e);
        std::process::exit(1);
    });

    let key_prefix = format!("vk_{}", hex::encode(&secret[..4]));

    let (wrapped_master_key, encrypted_private_key, public_key): (
        Option<Vec<u8>>,
        Vec<u8>,
        Option<Vec<u8>>,
    ) = if scoped {
        // Scoped key: generate X25519 keypair, wrap private key with API wrapping key
        eprintln!("Generating scoped API key...");
        let (privkey, pubkey) = generate_x25519_keypair();
        let wrapped_privkey = wrap_master_key(&wrapping_key, &MasterKey::from_bytes(privkey))
            .unwrap_or_else(|e| {
                eprintln!("error wrapping private key: {}", e);
                std::process::exit(1);
            });
        (None, wrapped_privkey, Some(pubkey.to_vec()))
    } else {
        // Full-access key: wrap user's master key
        let password = prompt_password("Password (to wrap master key): ");
        eprintln!("Deriving master key...");
        let master_key = derive_master_key(password.as_bytes(), &session.client_salt)
            .unwrap_or_else(|e| {
                eprintln!("error: key derivation failed: {}", e);
                std::process::exit(1);
            });

        eprintln!("Wrapping master key...");
        let wmk = wrap_master_key(&wrapping_key, &master_key).unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

        // Get user's encrypted_private_key from /auth/me
        let me_resp = client
            .get(format!("{}/auth/me", api_url))
            .header("Authorization", format!("Bearer {}", session.jwt))
            .send()
            .unwrap_or_else(|e| {
                eprintln!("error: {}", e);
                std::process::exit(1);
            });
        if !me_resp.status().is_success() {
            eprintln!("error: session expired. Run `vault-cli login` again");
            std::process::exit(1);
        }
        let me: serde_json::Value = me_resp.json().expect("invalid JSON");
        let epk = json_to_bytes(&me["encrypted_private_key"]);

        (Some(wmk), epk, None)
    };

    let expires_at = expires.map(|e| {
        let now = chrono::Utc::now();
        let duration = parse_duration(e);
        (now + duration).to_rfc3339()
    });

    let mut body = serde_json::json!({
        "name": name,
        "auth_key": hex::encode(auth_key),
        "key_prefix": key_prefix,
        "encrypted_private_key": encrypted_private_key,
        "scopes": {"read_only": read_only},
    });
    if let Some(wmk) = &wrapped_master_key {
        body["wrapped_master_key"] = serde_json::json!(wmk);
    }
    if let Some(pk) = &public_key {
        body["public_key"] = serde_json::json!(pk);
    }
    if let Some(exp) = expires_at {
        body["expires_at"] = serde_json::Value::String(exp);
    }

    let resp = client
        .post(format!("{}/api-keys", api_url))
        .header("Authorization", format!("Bearer {}", session.jwt))
        .json(&body)
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

    if !resp.status().is_success() {
        let text = resp.text().unwrap_or_default();
        eprintln!("error: failed to create API key: {}", text);
        std::process::exit(1);
    }

    let result: serde_json::Value = resp.json().expect("invalid JSON");
    let display_key = format!(
        "vk_{}_{}",
        hex::encode(&secret[..4]),
        URL_SAFE_NO_PAD.encode(secret)
    );

    eprintln!();
    eprintln!("API key created: {}", result["name"].as_str().unwrap_or(""));
    eprintln!("ID: {}", result["id"].as_str().unwrap_or(""));
    if scoped {
        eprintln!("Type: scoped (grant items with `vault-cli apikey grant`)");
    } else {
        eprintln!("Type: full access");
    }
    if read_only {
        eprintln!("Scope: read-only");
    }
    eprintln!();
    eprintln!("Key (shown once — store it securely):");
    eprintln!();
    println!("{}", display_key);
    eprintln!();
    eprintln!("Usage: export VAULT_API_KEY={}", display_key);
}

fn parse_duration(s: &str) -> chrono::Duration {
    let s = s.trim();
    if let Some(hours) = s.strip_suffix('h') {
        chrono::Duration::hours(hours.parse().expect("invalid number of hours"))
    } else if let Some(days) = s.strip_suffix('d') {
        chrono::Duration::days(days.parse().expect("invalid number of days"))
    } else if let Some(years) = s.strip_suffix('y') {
        chrono::Duration::days(years.parse::<i64>().expect("invalid number of years") * 365)
    } else {
        eprintln!(
            "error: invalid expiry format '{}' (use e.g. '24h', '7d', or '1y')",
            s
        );
        std::process::exit(1);
    }
}

fn run_apikey_list(client: &reqwest::blocking::Client, api_url: &str) {
    let session = load_session().unwrap_or_else(|| {
        eprintln!("error: not logged in");
        std::process::exit(1);
    });

    let resp = client
        .get(format!("{}/api-keys", api_url))
        .header("Authorization", format!("Bearer {}", session.jwt))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

    if !resp.status().is_success() {
        let text = resp.text().unwrap_or_default();
        eprintln!("error: {}", text);
        std::process::exit(1);
    }

    let keys: Vec<serde_json::Value> = resp.json().expect("invalid JSON");
    if keys.is_empty() {
        eprintln!("No API keys found.");
        return;
    }

    println!(
        "{:<38} {:<20} {:<14} {:<10} LAST USED",
        "ID", "NAME", "PREFIX", "SCOPE"
    );
    println!("{}", "-".repeat(95));
    for k in &keys {
        let scope = if k["scopes"]["read_only"].as_bool() == Some(true) {
            "read-only"
        } else {
            "read-write"
        };
        let last_used = k["last_used_at"]
            .as_str()
            .map(|s| s[..10].to_string())
            .unwrap_or_else(|| "never".to_string());
        println!(
            "{:<38} {:<20} {:<14} {:<10} {}",
            k["id"].as_str().unwrap_or("?"),
            k["name"].as_str().unwrap_or("?"),
            k["key_prefix"].as_str().unwrap_or("?"),
            scope,
            last_used,
        );
    }
}

fn run_apikey_revoke(client: &reqwest::blocking::Client, api_url: &str, id: &str) {
    let session = load_session().unwrap_or_else(|| {
        eprintln!("error: not logged in");
        std::process::exit(1);
    });

    let resp = client
        .delete(format!("{}/api-keys/{}", api_url, id))
        .header("Authorization", format!("Bearer {}", session.jwt))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

    if !resp.status().is_success() {
        let text = resp.text().unwrap_or_default();
        eprintln!("error: {}", text);
        std::process::exit(1);
    }

    eprintln!("API key revoked.");
}

fn run_apikey_grant(client: &reqwest::blocking::Client, api_url: &str, key_id: &str, label: &str) {
    let session = load_session().unwrap_or_else(|| {
        eprintln!("error: not logged in");
        std::process::exit(1);
    });

    let password = prompt_password("Password: ");
    let master_key =
        derive_master_key(password.as_bytes(), &session.client_salt).unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

    // Find the API key's public key
    let keys_resp = client
        .get(format!("{}/api-keys", api_url))
        .header("Authorization", format!("Bearer {}", session.jwt))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });
    if !keys_resp.status().is_success() {
        eprintln!("error: failed to list API keys");
        std::process::exit(1);
    }
    let keys: Vec<serde_json::Value> = keys_resp.json().expect("invalid JSON");
    let api_key = keys
        .iter()
        .find(|k| k["id"].as_str() == Some(key_id))
        .unwrap_or_else(|| {
            eprintln!("error: API key '{}' not found", key_id);
            std::process::exit(1);
        });
    let api_pubkey_bytes = json_to_bytes(&api_key["public_key"]);
    if api_pubkey_bytes.len() != 32 {
        eprintln!("error: API key '{}' is not a scoped key", key_id);
        std::process::exit(1);
    }
    let mut api_pubkey = [0u8; 32];
    api_pubkey.copy_from_slice(&api_pubkey_bytes);

    // Find the item by label
    let auth = AuthContext::Full {
        jwt: session.jwt.clone(),
        master_key,
        api_url: api_url.to_string(),
    };
    let secrets = fetch_and_decrypt_secrets(client, &auth);
    let (item_id, _, _) = secrets
        .iter()
        .find(|(_, blob, _)| blob.display_name() == label)
        .unwrap_or_else(|| {
            eprintln!("error: secret '{}' not found", label);
            std::process::exit(1);
        });

    // Unwrap the item key using master key
    let mk = match &auth {
        AuthContext::Full { master_key, .. } => master_key,
        _ => unreachable!(),
    };
    let enc_key = derive_subkey(mk, b"vault-enc").unwrap_or_else(|e| {
        eprintln!("error: {}", e);
        std::process::exit(1);
    });

    // Fetch the item to get wrapped_key and nonce
    let item_resp = client
        .get(format!("{}/items/{}", api_url, item_id))
        .header("Authorization", format!("Bearer {}", session.jwt))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });
    if !item_resp.status().is_success() {
        eprintln!("error: failed to fetch item");
        std::process::exit(1);
    }
    let item: serde_json::Value = item_resp.json().expect("invalid JSON");
    let wrapped_key = json_to_bytes(&item["wrapped_key"]);
    let nonce = json_to_bytes(&item["nonce"]);

    let item_key_plain = decrypt_item(&enc_key, &wrapped_key, &nonce).unwrap_or_else(|e| {
        eprintln!("error decrypting item key: {}", e);
        std::process::exit(1);
    });
    let mut item_key = [0u8; 32];
    item_key.copy_from_slice(&item_key_plain);

    // Wrap item key for the API key's public key
    let grant_wrap = wrap_key_for_recipient(&item_key, &api_pubkey).unwrap_or_else(|e| {
        eprintln!("error wrapping key: {}", e);
        std::process::exit(1);
    });

    // POST the grant
    let resp = client
        .post(format!("{}/api-keys/{}/grants", api_url, key_id))
        .header("Authorization", format!("Bearer {}", session.jwt))
        .json(&serde_json::json!({
            "item_id": item_id,
            "wrapped_key": grant_wrap.wrapped_key,
            "ephemeral_pubkey": grant_wrap.ephemeral_pubkey.to_vec(),
            "nonce": grant_wrap.nonce.to_vec(),
        }))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

    if !resp.status().is_success() {
        let text = resp.text().unwrap_or_default();
        eprintln!("error: {}", text);
        std::process::exit(1);
    }

    eprintln!("Granted '{}' to API key {}.", label, key_id);
}

fn run_apikey_grants(client: &reqwest::blocking::Client, api_url: &str, key_id: &str) {
    let session = load_session().unwrap_or_else(|| {
        eprintln!("error: not logged in");
        std::process::exit(1);
    });

    let resp = client
        .get(format!("{}/api-keys/{}/grants", api_url, key_id))
        .header("Authorization", format!("Bearer {}", session.jwt))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

    if !resp.status().is_success() {
        let text = resp.text().unwrap_or_default();
        eprintln!("error: {}", text);
        std::process::exit(1);
    }

    let grants: Vec<serde_json::Value> = resp.json().expect("invalid JSON");
    if grants.is_empty() {
        eprintln!("No items granted to this API key.");
        return;
    }

    println!("{:<38} {:<38} CREATED", "GRANT ID", "ITEM ID");
    println!("{}", "-".repeat(90));
    for g in &grants {
        println!(
            "{:<38} {:<38} {}",
            g["id"].as_str().unwrap_or("?"),
            g["item_id"].as_str().unwrap_or("?"),
            g["created_at"].as_str().map(|s| &s[..10]).unwrap_or("?"),
        );
    }
}

fn run_apikey_ungrant(
    client: &reqwest::blocking::Client,
    api_url: &str,
    key_id: &str,
    label: &str,
) {
    let session = load_session().unwrap_or_else(|| {
        eprintln!("error: not logged in");
        std::process::exit(1);
    });

    let password = prompt_password("Password: ");
    let master_key =
        derive_master_key(password.as_bytes(), &session.client_salt).unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

    let auth = AuthContext::Full {
        jwt: session.jwt.clone(),
        master_key,
        api_url: api_url.to_string(),
    };
    let secrets = fetch_and_decrypt_secrets(client, &auth);
    let (target_item_id, _, _) = secrets
        .iter()
        .find(|(_, blob, _)| blob.display_name() == label)
        .unwrap_or_else(|| {
            eprintln!("error: secret '{}' not found", label);
            std::process::exit(1);
        });

    // Fetch grants for this key, find the one matching the item
    let grants_resp = client
        .get(format!("{}/api-keys/{}/grants", api_url, key_id))
        .header("Authorization", format!("Bearer {}", session.jwt))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });
    if !grants_resp.status().is_success() {
        let text = grants_resp.text().unwrap_or_default();
        eprintln!("error: {}", text);
        std::process::exit(1);
    }
    let grants: Vec<serde_json::Value> = grants_resp.json().expect("invalid JSON");
    let grant = grants
        .iter()
        .find(|g| g["item_id"].as_str() == Some(target_item_id.as_str()))
        .unwrap_or_else(|| {
            eprintln!("error: '{}' is not granted to this API key", label);
            std::process::exit(1);
        });
    let grant_id = grant["id"].as_str().unwrap();

    let resp = client
        .delete(format!(
            "{}/api-keys/{}/grants/{}",
            api_url, key_id, grant_id
        ))
        .header("Authorization", format!("Bearer {}", session.jwt))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

    if !resp.status().is_success() {
        let text = resp.text().unwrap_or_default();
        eprintln!("error: {}", text);
        std::process::exit(1);
    }

    eprintln!("Revoked '{}' from API key {}.", label, key_id);
}

fn run_apikey_rotate(client: &reqwest::blocking::Client, api_url: &str, key_ref: &str) {
    let session = load_session().unwrap_or_else(|| {
        eprintln!("error: not logged in. Run `vault-cli login` first");
        std::process::exit(1);
    });

    // Find the key to rotate by ID or prefix
    let keys_resp = client
        .get(format!("{}/api-keys", api_url))
        .header("Authorization", format!("Bearer {}", session.jwt))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });
    if !keys_resp.status().is_success() {
        eprintln!("error: failed to list API keys");
        std::process::exit(1);
    }
    let keys: Vec<serde_json::Value> = keys_resp.json().expect("invalid JSON");
    let old_key = keys
        .iter()
        .find(|k| k["id"].as_str() == Some(key_ref) || k["key_prefix"].as_str() == Some(key_ref))
        .unwrap_or_else(|| {
            eprintln!("error: API key '{}' not found", key_ref);
            std::process::exit(1);
        });

    let old_id = old_key["id"].as_str().unwrap().to_string();
    let old_name = old_key["name"].as_str().unwrap_or("").to_string();
    let old_scopes = old_key["scopes"].clone();
    let is_scoped = old_key["is_scoped"].as_bool() == Some(true);

    eprintln!("Rotating API key: {} ({})", old_name, old_id);

    // Generate new secret
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);

    let (wrapping_key, auth_key) = derive_api_key_keys(&secret).unwrap_or_else(|e| {
        eprintln!("error: {}", e);
        std::process::exit(1);
    });

    let key_prefix = format!("vk_{}", hex::encode(&secret[..4]));

    struct KeyMaterial {
        wrapped_master_key: Option<Vec<u8>>,
        encrypted_private_key: Vec<u8>,
        public_key: Option<Vec<u8>>,
        new_privkey: Option<[u8; 32]>,
    }

    let km = if is_scoped {
        let (privkey, pubkey) = generate_x25519_keypair();
        let wrapped_privkey = wrap_master_key(&wrapping_key, &MasterKey::from_bytes(privkey))
            .unwrap_or_else(|e| {
                eprintln!("error wrapping private key: {}", e);
                std::process::exit(1);
            });
        KeyMaterial {
            wrapped_master_key: None,
            encrypted_private_key: wrapped_privkey,
            public_key: Some(pubkey.to_vec()),
            new_privkey: Some(privkey),
        }
    } else {
        let password = prompt_password("Password (to wrap master key): ");
        eprintln!("Deriving master key...");
        let master_key = derive_master_key(password.as_bytes(), &session.client_salt)
            .unwrap_or_else(|e| {
                eprintln!("error: {}", e);
                std::process::exit(1);
            });

        let wmk = wrap_master_key(&wrapping_key, &master_key).unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

        let me_resp = client
            .get(format!("{}/auth/me", api_url))
            .header("Authorization", format!("Bearer {}", session.jwt))
            .send()
            .unwrap_or_else(|e| {
                eprintln!("error: {}", e);
                std::process::exit(1);
            });
        if !me_resp.status().is_success() {
            eprintln!("error: session expired. Run `vault-cli login` again");
            std::process::exit(1);
        }
        let me: serde_json::Value = me_resp.json().expect("invalid JSON");
        let epk = json_to_bytes(&me["encrypted_private_key"]);

        KeyMaterial {
            wrapped_master_key: Some(wmk),
            encrypted_private_key: epk,
            public_key: None,
            new_privkey: None,
        }
    };

    let new_name = format!("{} (rotated)", old_name);

    let mut body = serde_json::json!({
        "name": new_name,
        "auth_key": hex::encode(auth_key),
        "key_prefix": key_prefix,
        "encrypted_private_key": km.encrypted_private_key,
        "scopes": old_scopes,
    });
    if let Some(wmk) = &km.wrapped_master_key {
        body["wrapped_master_key"] = serde_json::json!(wmk);
    }
    if let Some(pk) = &km.public_key {
        body["public_key"] = serde_json::json!(pk);
    }

    let resp = client
        .post(format!("{}/api-keys", api_url))
        .header("Authorization", format!("Bearer {}", session.jwt))
        .json(&body)
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

    if !resp.status().is_success() {
        let text = resp.text().unwrap_or_default();
        eprintln!("error: failed to create new API key: {}", text);
        std::process::exit(1);
    }

    let new_key_resp: serde_json::Value = resp.json().expect("invalid JSON");
    let new_id = new_key_resp["id"].as_str().unwrap().to_string();

    // Re-grant items if scoped
    if is_scoped {
        let new_pubkey_bytes = json_to_bytes(&new_key_resp["public_key"]);
        let mut new_pubkey = [0u8; 32];
        new_pubkey.copy_from_slice(&new_pubkey_bytes);

        // Get old key's private key to unwrap grants
        // We need the old API key's private key. The user doesn't have the old secret anymore
        // if they're rotating, so we need the master key to re-wrap from source items.
        let password = if km.new_privkey.is_some() {
            // Already prompted for scoped path — need master key for item access
            prompt_password("Password (to re-grant items): ")
        } else {
            unreachable!()
        };
        let master_key = derive_master_key(password.as_bytes(), &session.client_salt)
            .unwrap_or_else(|e| {
                eprintln!("error: {}", e);
                std::process::exit(1);
            });
        let enc_key = derive_subkey(&master_key, b"vault-enc").unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

        let grants_resp = client
            .get(format!("{}/api-keys/{}/grants", api_url, old_id))
            .header("Authorization", format!("Bearer {}", session.jwt))
            .send()
            .unwrap_or_else(|e| {
                eprintln!("error: {}", e);
                std::process::exit(1);
            });
        if grants_resp.status().is_success() {
            let grants: Vec<serde_json::Value> = grants_resp.json().expect("invalid JSON");
            for grant in &grants {
                let item_id = grant["item_id"].as_str().unwrap_or("");

                // Fetch item to get wrapped_key + nonce
                let item_resp = client
                    .get(format!("{}/items/{}", api_url, item_id))
                    .header("Authorization", format!("Bearer {}", session.jwt))
                    .send();
                let item: serde_json::Value = match item_resp {
                    Ok(r) if r.status().is_success() => r.json().unwrap_or_default(),
                    _ => {
                        eprintln!("warning: could not fetch item {}, skipping grant", item_id);
                        continue;
                    }
                };

                let wrapped_key = json_to_bytes(&item["wrapped_key"]);
                let nonce = json_to_bytes(&item["nonce"]);

                let item_key_plain = match decrypt_item(&enc_key, &wrapped_key, &nonce) {
                    Ok(k) => k,
                    Err(e) => {
                        eprintln!("warning: could not decrypt item key for {}: {}", item_id, e);
                        continue;
                    }
                };
                let mut item_key = [0u8; 32];
                item_key.copy_from_slice(&item_key_plain);

                // Wrap for new API key's public key
                let grant_wrap =
                    wrap_key_for_recipient(&item_key, &new_pubkey).unwrap_or_else(|e| {
                        eprintln!("error wrapping key for grant: {}", e);
                        std::process::exit(1);
                    });

                let resp = client
                    .post(format!("{}/api-keys/{}/grants", api_url, new_id))
                    .header("Authorization", format!("Bearer {}", session.jwt))
                    .json(&serde_json::json!({
                        "item_id": item_id,
                        "wrapped_key": grant_wrap.wrapped_key,
                        "ephemeral_pubkey": grant_wrap.ephemeral_pubkey.to_vec(),
                        "nonce": grant_wrap.nonce.to_vec(),
                    }))
                    .send();

                match resp {
                    Ok(r) if r.status().is_success() => {
                        eprintln!("  Re-granted item {}", item_id);
                    }
                    _ => {
                        eprintln!("warning: failed to re-grant item {}", item_id);
                    }
                }
            }
        }
    }

    // Revoke old key
    let resp = client
        .delete(format!("{}/api-keys/{}", api_url, old_id))
        .header("Authorization", format!("Bearer {}", session.jwt))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

    if !resp.status().is_success() {
        eprintln!(
            "warning: new key created but failed to revoke old key {}",
            old_id
        );
    }

    let display_key = format!(
        "vk_{}_{}",
        hex::encode(&secret[..4]),
        URL_SAFE_NO_PAD.encode(secret)
    );

    eprintln!();
    eprintln!("Rotated: {} -> {}", old_id, new_id);
    eprintln!("New key (shown once — store it securely):");
    eprintln!();
    println!("{}", display_key);
    eprintln!();
    eprintln!("Usage: export VAULT_API_KEY={}", display_key);
}

// --- Grant commands ---

fn run_grant(client: &reqwest::blocking::Client, api_url: &str, action: GrantAction) {
    match action {
        GrantAction::Create {
            label,
            to,
            max_views,
            expires,
            read_only,
        } => run_grant_create(
            client,
            api_url,
            &label,
            &to,
            max_views,
            expires.as_deref(),
            read_only,
        ),
        GrantAction::List { sent, received } => run_grant_list(client, api_url, sent, received),
        GrantAction::Access { id, output } => run_grant_access(client, api_url, &id, output),
        GrantAction::Revoke { id } => run_grant_revoke(client, api_url, &id),
        GrantAction::Resend { id } => run_grant_resend(client, api_url, &id),
    }
}

fn run_grant_create(
    client: &reqwest::blocking::Client,
    api_url: &str,
    label: &str,
    to_email: &str,
    max_views: Option<u32>,
    expires: Option<&str>,
    read_only: bool,
) {
    let auth = get_auth(client, api_url);
    let (jwt, master_key, effective_url) = match &auth {
        AuthContext::Full {
            jwt,
            master_key,
            api_url,
        } => (jwt.as_str(), master_key, api_url.as_str()),
        AuthContext::Scoped { .. } => {
            eprintln!("error: scoped API keys cannot create grants");
            std::process::exit(1);
        }
    };

    // Find the item by label
    let secrets = fetch_and_decrypt_secrets(client, &auth);
    let (item_id, _, _) = secrets
        .iter()
        .find(|(_, blob, _)| blob.display_name() == label)
        .unwrap_or_else(|| {
            eprintln!("error: secret '{}' not found", label);
            std::process::exit(1);
        });

    // Decrypt item key
    let enc_key = derive_subkey(master_key, b"vault-enc").unwrap_or_else(|e| {
        eprintln!("error: {}", e);
        std::process::exit(1);
    });

    let item_resp = client
        .get(format!("{}/items/{}", effective_url, item_id))
        .header("Authorization", format!("Bearer {}", jwt))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });
    if !item_resp.status().is_success() {
        eprintln!("error: failed to fetch item");
        std::process::exit(1);
    }
    let item: serde_json::Value = item_resp.json().expect("invalid JSON");
    let wrapped_key = json_to_bytes(&item["wrapped_key"]);
    let nonce = json_to_bytes(&item["nonce"]);

    let user_id = load_session().map(|s| s.user_id).unwrap_or_default();
    let wrap_aad = if user_id.is_empty() {
        Vec::new()
    } else {
        format!("wrap:{}", user_id).into_bytes()
    };
    let item_key_plain =
        vault_core::crypto::decrypt_item_auto(&enc_key, &wrapped_key, &nonce, &wrap_aad)
            .unwrap_or_else(|e| {
                eprintln!("error decrypting item key: {}", e);
                std::process::exit(1);
            });
    let mut item_key = [0u8; 32];
    item_key.copy_from_slice(&item_key_plain);

    // Fetch recipient's public key
    let pk_resp = client
        .get(format!("{}/users/public-key", effective_url))
        .query(&[("email", to_email)])
        .header("Authorization", format!("Bearer {}", jwt))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });
    if !pk_resp.status().is_success() {
        if pk_resp.status().as_u16() == 404 {
            eprintln!(
                "error: user '{}' not found or has no keys (must be a verified BlindKeep user)",
                to_email
            );
        } else {
            eprintln!("error: failed to fetch public key for '{}'", to_email);
        }
        std::process::exit(1);
    }
    let pk_body: serde_json::Value = pk_resp.json().expect("invalid JSON");
    let recipient_pubkey_bytes = json_to_bytes(&pk_body["public_key"]);
    if recipient_pubkey_bytes.len() != 32 {
        eprintln!("error: recipient has invalid public key");
        std::process::exit(1);
    }
    let mut recipient_pubkey = [0u8; 32];
    recipient_pubkey.copy_from_slice(&recipient_pubkey_bytes);

    // Wrap item key for recipient (V1 key-bound, grant format: nonce || ciphertext)
    let (grant_wrapped_key, ephemeral_pubkey) = wrap_key_for_grant(&item_key, &recipient_pubkey)
        .unwrap_or_else(|e| {
            eprintln!("error wrapping key: {}", e);
            std::process::exit(1);
        });

    // Build policy
    let allowed_ops = if read_only {
        serde_json::json!(["view"])
    } else {
        serde_json::json!(["view", "download"])
    };
    let mut policy = serde_json::json!({
        "allowed_ops": allowed_ops,
        "notify_on_access": false,
    });
    if let Some(n) = max_views {
        policy["max_views"] = serde_json::json!(n);
    }
    if let Some(exp) = expires {
        let duration = parse_duration(exp);
        let expires_at = (chrono::Utc::now() + duration).to_rfc3339();
        policy["expires_at"] = serde_json::json!(expires_at);
    }

    // POST /grants
    let resp = client
        .post(format!("{}/grants", effective_url))
        .header("Authorization", format!("Bearer {}", jwt))
        .json(&serde_json::json!({
            "item_id": item_id,
            "grantee_email": to_email,
            "wrapped_key": grant_wrapped_key,
            "ephemeral_pubkey": ephemeral_pubkey.to_vec(),
            "policy": policy,
        }))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

    if !resp.status().is_success() {
        let text = resp.text().unwrap_or_default();
        eprintln!("error: {}", text);
        std::process::exit(1);
    }

    let body: serde_json::Value = resp.json().unwrap_or_default();
    let grant_id = body["id"].as_str().unwrap_or("(unknown)");
    eprintln!("Grant created: {} -> {}", label, to_email);
    eprintln!("Grant ID: {}", grant_id);
}

fn run_grant_list(
    client: &reqwest::blocking::Client,
    api_url: &str,
    sent_only: bool,
    received_only: bool,
) {
    let session = load_session().unwrap_or_else(|| {
        eprintln!("error: not logged in");
        std::process::exit(1);
    });

    let resp = client
        .get(format!("{}/grants", api_url))
        .header("Authorization", format!("Bearer {}", session.jwt))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

    if !resp.status().is_success() {
        let text = resp.text().unwrap_or_default();
        eprintln!("error: {}", text);
        std::process::exit(1);
    }

    let grants: Vec<serde_json::Value> = resp.json().expect("invalid JSON");

    let filtered: Vec<_> = grants
        .iter()
        .filter(|g| {
            if sent_only {
                g["grantor_id"].as_str() == Some(&session.user_id)
            } else if received_only {
                g["grantor_id"].as_str() != Some(&session.user_id)
            } else {
                true
            }
        })
        .collect();

    if filtered.is_empty() {
        eprintln!("No grants found.");
        return;
    }

    println!(
        "{:<38} {:<6} {:<30} {:<10} CREATED",
        "GRANT ID", "DIR", "EMAIL", "STATUS"
    );
    println!("{}", "-".repeat(96));
    for g in &filtered {
        let is_sent = g["grantor_id"].as_str() == Some(&session.user_id);
        let dir = if is_sent { "sent" } else { "recv" };
        let email = if is_sent {
            g["grantee_email"].as_str().unwrap_or("?")
        } else {
            g["grantor_email"].as_str().unwrap_or("?")
        };
        println!(
            "{:<38} {:<6} {:<30} {:<10} {}",
            g["id"].as_str().unwrap_or("?"),
            dir,
            email,
            g["status"].as_str().unwrap_or("?"),
            g["created_at"].as_str().map(|s| &s[..10]).unwrap_or("?"),
        );
    }
}

fn run_grant_access(
    client: &reqwest::blocking::Client,
    api_url: &str,
    grant_id: &str,
    output: Option<PathBuf>,
) {
    let auth = get_auth(client, api_url);
    let (jwt, master_key, effective_url) = match &auth {
        AuthContext::Full {
            jwt,
            master_key,
            api_url,
        } => (jwt.as_str(), master_key, api_url.as_str()),
        AuthContext::Scoped { .. } => {
            eprintln!("error: scoped API keys cannot access grants");
            std::process::exit(1);
        }
    };

    // Access the grant
    let resp = client
        .post(format!("{}/grants/{}/access", effective_url, grant_id))
        .header("Authorization", format!("Bearer {}", jwt))
        .json(&serde_json::json!({"operation": "view"}))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let text = resp.text().unwrap_or_default();
        match status {
            403 => eprintln!("error: access denied (grant may be expired or policy violation)"),
            404 => eprintln!("error: grant not found or revoked"),
            _ => eprintln!("error: {}", text),
        }
        std::process::exit(1);
    }

    let body: serde_json::Value = resp.json().expect("invalid JSON");

    // Extract grant key material
    let grant_wrapped_key = json_to_bytes(&body["wrapped_key"]);
    let ephemeral_pubkey = json_to_bytes(&body["ephemeral_pubkey"]);
    if ephemeral_pubkey.len() != 32 {
        eprintln!("error: invalid grant data (bad ephemeral pubkey)");
        std::process::exit(1);
    }
    let mut eph_pub = [0u8; 32];
    eph_pub.copy_from_slice(&ephemeral_pubkey);

    // Decrypt user's private key
    let enc_key = derive_subkey(master_key, b"vault-enc").unwrap_or_else(|e| {
        eprintln!("error: {}", e);
        std::process::exit(1);
    });

    let me_resp = client
        .get(format!("{}/auth/me", effective_url))
        .header("Authorization", format!("Bearer {}", jwt))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });
    if !me_resp.status().is_success() {
        eprintln!("error: failed to fetch profile");
        std::process::exit(1);
    }
    let me: serde_json::Value = me_resp.json().expect("invalid JSON");
    let encrypted_privkey = json_to_bytes(&me["encrypted_private_key"]);
    let my_pubkey_bytes = json_to_bytes(&me["public_key"]);

    let private_key = decrypt_private_key(&enc_key, &encrypted_privkey).unwrap_or_else(|e| {
        eprintln!("error decrypting private key: {}", e);
        std::process::exit(1);
    });

    if my_pubkey_bytes.len() != 32 {
        eprintln!("error: invalid public key on your account");
        std::process::exit(1);
    }
    let mut my_pubkey = [0u8; 32];
    my_pubkey.copy_from_slice(&my_pubkey_bytes);

    // Unwrap item key (auto-detects V0/V1)
    let item_key = unwrap_grant_key(&private_key, &eph_pub, &grant_wrapped_key, &my_pubkey)
        .unwrap_or_else(|e| {
            eprintln!("error unwrapping grant key: {}", e);
            std::process::exit(1);
        });

    // Decrypt the blob — nonce is embedded: 0x01 + nonce(24) + ciphertext (V1)
    //                                   or: nonce(24) + ciphertext (V0)
    let encrypted_blob_b64 = body["encrypted_blob"].as_str().unwrap_or("");
    let blob_data = STANDARD.decode(encrypted_blob_b64).unwrap_or_else(|e| {
        eprintln!("error decoding blob: {}", e);
        std::process::exit(1);
    });
    if blob_data.len() < 25 {
        eprintln!("error: encrypted blob too short");
        std::process::exit(1);
    }

    let grantor_id = body["grantor_id"].as_str().unwrap_or("");
    let blob_aad = if grantor_id.is_empty() {
        Vec::new()
    } else {
        format!("item:{}", grantor_id).into_bytes()
    };

    let plaintext = if blob_data[0] == 0x01 && blob_data.len() > 25 {
        let nonce = &blob_data[1..25];
        let ciphertext = &blob_data[25..];
        vault_core::crypto::decrypt_item_auto(&item_key, ciphertext, nonce, &blob_aad)
            .or_else(|_| decrypt_item(&item_key, &blob_data[24..], &blob_data[..24]))
    } else {
        decrypt_item(&item_key, &blob_data[24..], &blob_data[..24])
    }
    .unwrap_or_else(|e| {
        eprintln!("error decrypting grant content: {}", e);
        std::process::exit(1);
    });

    // Try to parse as SecretBlob (CLI-created items)
    if let Ok(blob) = serde_json::from_slice::<SecretBlob>(&plaintext) {
        if let Some(path) = output {
            std::fs::write(&path, blob.secret_value().unwrap_or("")).unwrap_or_else(|e| {
                eprintln!("error writing {}: {}", path.display(), e);
                std::process::exit(1);
            });
            eprintln!("Written to {}", path.display());
        } else {
            print!("{}", blob.secret_value().unwrap_or(""));
        }
    } else {
        // Raw content (e.g., web-created items)
        if let Some(path) = output {
            std::fs::write(&path, &*plaintext).unwrap_or_else(|e| {
                eprintln!("error writing {}: {}", path.display(), e);
                std::process::exit(1);
            });
            eprintln!("Written to {}", path.display());
        } else if let Ok(text) = std::str::from_utf8(&plaintext) {
            print!("{}", text);
        } else {
            eprintln!("error: grant content is binary (use -o to save to file)");
            std::process::exit(1);
        }
    }
}

fn run_grant_revoke(client: &reqwest::blocking::Client, api_url: &str, grant_id: &str) {
    let session = load_session().unwrap_or_else(|| {
        eprintln!("error: not logged in");
        std::process::exit(1);
    });

    let resp = client
        .delete(format!("{}/grants/{}", api_url, grant_id))
        .header("Authorization", format!("Bearer {}", session.jwt))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

    if !resp.status().is_success() {
        let text = resp.text().unwrap_or_default();
        eprintln!("error: {}", text);
        std::process::exit(1);
    }

    eprintln!("Grant {} revoked.", grant_id);
}

fn run_grant_resend(client: &reqwest::blocking::Client, api_url: &str, grant_id: &str) {
    let session = load_session().unwrap_or_else(|| {
        eprintln!("error: not logged in");
        std::process::exit(1);
    });

    let resp = client
        .post(format!("{}/grants/{}/resend", api_url, grant_id))
        .header("Authorization", format!("Bearer {}", session.jwt))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let text = resp.text().unwrap_or_default();
        if status == 400 {
            eprintln!("error: cannot resend (grant may not be pending or is a link-secret grant)");
        } else {
            eprintln!("error: {}", text);
        }
        std::process::exit(1);
    }

    eprintln!("Grant notification resent for {}.", grant_id);
}

// --- Secret CRUD ---

/// Encrypted envelope format (compatible with web UI).
/// The `name` field is the display name / secret label.
/// The `content` field holds the secret value.
#[derive(serde::Serialize, serde::Deserialize)]
struct SecretBlob {
    name: String,
    #[serde(default)]
    content: Option<String>,
    // Legacy CLI format compatibility
    #[serde(default)]
    label: Option<String>,
    #[serde(default, alias = "type", alias = "item_type")]
    item_type: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    filename: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mime_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    file_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    file_wrapped_key: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    file_nonce: Option<Vec<u8>>,
}

impl SecretBlob {
    fn display_name(&self) -> &str {
        if !self.name.is_empty() {
            &self.name
        } else {
            self.label.as_deref().unwrap_or("Untitled")
        }
    }

    fn secret_value(&self) -> Option<&str> {
        self.content.as_deref().or(self.value.as_deref())
    }

    fn is_secret(&self) -> bool {
        self.content.is_some() || self.item_type.as_deref() == Some("secret")
    }

    fn is_file(&self) -> bool {
        self.item_type.as_deref() == Some("file")
            || (self.item_type.as_deref() == Some("document") && self.filename.is_some())
    }
}

fn decrypt_item_blob(
    client: &reqwest::blocking::Client,
    api_url: &str,
    jwt: &str,
    item_id: &str,
    item_key: &[u8; 32],
    user_id: &str,
) -> Option<SecretBlob> {
    let blob_resp = client
        .get(format!("{}/items/{}/blob", api_url, item_id))
        .header("Authorization", format!("Bearer {}", jwt))
        .send();

    let raw = match blob_resp {
        Ok(r) if r.status().is_success() => r.bytes().unwrap_or_default().to_vec(),
        _ => return None,
    };

    // S3 stores the base64-encoded blob; decode it to get the encrypted payload
    let blob_data = STANDARD.decode(&raw).unwrap_or(raw);

    if blob_data.len() < 25 {
        return None;
    }

    // V1 format: 0x01 + nonce(24) + ciphertext (with 0x01 prefix from encrypt_v1)
    // V0 format: nonce(24) + ciphertext
    let blob_aad = if user_id.is_empty() {
        Vec::new()
    } else {
        format!("item:{}", user_id).into_bytes()
    };
    let decrypted = if blob_data[0] == 0x01 && blob_data.len() > 25 {
        let nonce = &blob_data[1..25];
        let ciphertext = &blob_data[25..];
        vault_core::crypto::decrypt_item_auto(item_key, ciphertext, nonce, &blob_aad)
            .or_else(|_| {
                // Nonce happened to start with 0x01 — treat as V0
                decrypt_item(item_key, &blob_data[24..], &blob_data[..24])
            })
            .ok()?
    } else {
        decrypt_item(item_key, &blob_data[24..], &blob_data[..24]).ok()?
    };
    let blob: SecretBlob = serde_json::from_slice(&decrypted).ok()?;
    if blob.is_secret() || blob.is_file() {
        Some(blob)
    } else {
        None
    }
}

/// Decrypt a base64-encoded inline envelope (used for file items where encrypted_blob
/// is the metadata envelope, not the file data).
fn decrypt_inline_envelope(
    enc_blob_b64: &str,
    item_key: &[u8; 32],
    user_id: &str,
) -> Option<SecretBlob> {
    let blob_data = STANDARD.decode(enc_blob_b64).ok()?;
    if blob_data.len() < 25 {
        return None;
    }

    let blob_aad = if user_id.is_empty() {
        Vec::new()
    } else {
        format!("item:{}", user_id).into_bytes()
    };

    let decrypted = if blob_data[0] == 0x01 && blob_data.len() > 25 {
        let nonce = &blob_data[1..25];
        let ciphertext = &blob_data[25..];
        vault_core::crypto::decrypt_item_auto(item_key, ciphertext, nonce, &blob_aad)
            .or_else(|_| decrypt_item(item_key, &blob_data[24..], &blob_data[..24]))
            .ok()?
    } else {
        decrypt_item(item_key, &blob_data[24..], &blob_data[..24]).ok()?
    };

    // Envelope may be padded (web UI pads it)
    let envelope_bytes = unpad(&decrypted);
    let blob: SecretBlob = serde_json::from_slice(envelope_bytes).ok()?;
    if blob.is_secret() || blob.is_file() {
        Some(blob)
    } else {
        None
    }
}

fn fetch_and_decrypt_secrets(
    client: &reqwest::blocking::Client,
    auth: &AuthContext,
) -> Vec<(String, SecretBlob, String)> {
    match auth {
        AuthContext::Full {
            jwt,
            master_key,
            api_url,
        } => {
            let user_id = load_session().map(|s| s.user_id).unwrap_or_default();
            fetch_secrets_full(client, api_url, jwt, master_key, &user_id)
        }
        AuthContext::Scoped {
            jwt,
            api_privkey,
            api_key_id,
            api_url,
        } => fetch_secrets_scoped(client, api_url, jwt, api_privkey, api_key_id),
    }
}

fn fetch_secrets_full(
    client: &reqwest::blocking::Client,
    api_url: &str,
    jwt: &str,
    master_key: &MasterKey,
    user_id: &str,
) -> Vec<(String, SecretBlob, String)> {
    let resp = client
        .get(format!("{}/items", api_url))
        .header("Authorization", format!("Bearer {}", jwt))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

    if !resp.status().is_success() {
        let text = resp.text().unwrap_or_default();
        eprintln!("error: {}", text);
        std::process::exit(1);
    }

    let items: Vec<serde_json::Value> = resp.json().expect("invalid JSON");

    let enc_key = derive_subkey(master_key, b"vault-enc").unwrap_or_else(|e| {
        eprintln!("error deriving encryption key: {}", e);
        std::process::exit(1);
    });

    let wrap_aad = if user_id.is_empty() {
        Vec::new()
    } else {
        format!("wrap:{}", user_id).into_bytes()
    };

    let mut secrets = Vec::new();
    for item in &items {
        let item_id = item["id"].as_str().unwrap_or("").to_string();
        let wrapped_key = json_to_bytes(&item["wrapped_key"]);
        let nonce = json_to_bytes(&item["nonce"]);
        if wrapped_key.is_empty() || nonce.is_empty() {
            continue;
        }

        let item_key_plain = match vault_core::crypto::decrypt_item_auto(
            &enc_key,
            &wrapped_key,
            &nonce,
            &wrap_aad,
        ) {
            Ok(k) => k,
            Err(_) => continue,
        };
        if item_key_plain.len() != 32 {
            continue;
        }
        let mut item_key = [0u8; 32];
        item_key.copy_from_slice(&item_key_plain);

        // For file items, the envelope is inline in encrypted_blob (file data is at file_blob_key).
        // For regular items, fetch blob from /items/:id/blob.
        let has_file_blob = item["file_blob_key"]
            .as_str()
            .is_some_and(|s| !s.is_empty());
        let blob_opt = if has_file_blob {
            decrypt_inline_envelope(
                item["encrypted_blob"].as_str().unwrap_or(""),
                &item_key,
                user_id,
            )
        } else {
            decrypt_item_blob(client, api_url, jwt, &item_id, &item_key, user_id)
        };

        if let Some(blob) = blob_opt {
            secrets.push((
                item_id,
                blob,
                serde_json::to_string(item).unwrap_or_default(),
            ));
        }
    }

    secrets
}

fn fetch_secrets_scoped(
    client: &reqwest::blocking::Client,
    api_url: &str,
    jwt: &str,
    api_privkey: &[u8; 32],
    api_key_id: &str,
) -> Vec<(String, SecretBlob, String)> {
    // Fetch grants for this API key
    let resp = client
        .get(format!("{}/api-keys/{}/grants", api_url, api_key_id))
        .header("Authorization", format!("Bearer {}", jwt))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

    if !resp.status().is_success() {
        let text = resp.text().unwrap_or_default();
        eprintln!("error: {}", text);
        std::process::exit(1);
    }

    let grants: Vec<serde_json::Value> = resp.json().expect("invalid JSON");

    let mut secrets = Vec::new();
    for grant in &grants {
        let item_id = grant["item_id"].as_str().unwrap_or("").to_string();
        let wrapped_key = json_to_bytes(&grant["wrapped_key"]);
        let ephemeral_pubkey = json_to_bytes(&grant["ephemeral_pubkey"]);
        let nonce = json_to_bytes(&grant["nonce"]);

        if wrapped_key.is_empty() || ephemeral_pubkey.len() != 32 {
            continue;
        }
        let mut eph_pub = [0u8; 32];
        eph_pub.copy_from_slice(&ephemeral_pubkey);

        // Unwrap item key using API key's private key via X25519 DH
        let item_key = match unwrap_key(api_privkey, &eph_pub, &wrapped_key, &nonce) {
            Ok(k) => k,
            Err(_) => continue,
        };

        if let Some(blob) = decrypt_item_blob(client, api_url, jwt, &item_id, &item_key, "") {
            secrets.push((item_id, blob, String::new()));
        }
    }

    secrets
}

fn run_put(client: &reqwest::blocking::Client, api_url: &str, label: &str, value: Option<&str>) {
    let auth = get_auth(client, api_url);

    let secret_value = match value {
        Some(v) if v.starts_with('@') => {
            let path = &v[1..];
            std::fs::read_to_string(path).unwrap_or_else(|e| {
                eprintln!("error reading {}: {}", path, e);
                std::process::exit(1);
            })
        }
        Some(v) => v.to_string(),
        None => {
            let mut buf = String::new();
            std::io::stdin().read_line(&mut buf).unwrap_or_else(|e| {
                eprintln!("error reading stdin: {}", e);
                std::process::exit(1);
            });
            buf.trim_end().to_string()
        }
    };

    let blob = SecretBlob {
        name: label.to_string(),
        content: Some(secret_value),
        label: None,
        item_type: None,
        value: None,
        filename: None,
        mime_type: None,
        file_size: None,
        file_wrapped_key: None,
        file_nonce: None,
    };
    let blob_json = serde_json::to_vec(&blob).expect("serialize blob");

    // Generate random item key
    let mut item_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut item_key);

    let user_id = load_session().map(|s| s.user_id).unwrap_or_default();

    // Encrypt blob with item key (V1 with AAD)
    let blob_aad = format!("item:{}", user_id);
    let enc_blob = vault_core::crypto::encrypt_item_v1(&item_key, &blob_json, blob_aad.as_bytes())
        .unwrap_or_else(|e| {
            eprintln!("error encrypting: {}", e);
            std::process::exit(1);
        });

    // Build blob: 0x01 + nonce(24) + ciphertext (V1 concat format)
    let mut blob_data = Vec::with_capacity(1 + 24 + enc_blob.ciphertext.len());
    blob_data.push(0x01);
    blob_data.extend_from_slice(&enc_blob.nonce);
    blob_data.extend_from_slice(&enc_blob.ciphertext);
    let blob_b64 = STANDARD.encode(&blob_data);

    // Wrap item key with encryption subkey (V1 with AAD)
    let master_key = match &auth {
        AuthContext::Full { master_key, .. } => master_key,
        AuthContext::Scoped { .. } => {
            eprintln!("error: scoped API keys cannot create items");
            std::process::exit(1);
        }
    };
    let enc_key = derive_subkey(master_key, b"vault-enc").unwrap_or_else(|e| {
        eprintln!("error: {}", e);
        std::process::exit(1);
    });
    let wrap_aad = format!("wrap:{}", user_id);
    let wrapped = vault_core::crypto::encrypt_item_v1(&enc_key, &item_key, wrap_aad.as_bytes())
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

    let resp = client
        .post(format!("{}/items", auth.api_url()))
        .header("Authorization", format!("Bearer {}", auth.jwt()))
        .json(&serde_json::json!({
            "encrypted_blob": blob_b64,
            "wrapped_key": wrapped.ciphertext,
            "nonce": wrapped.nonce.to_vec(),
            "item_type": "encrypted",
        }))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

    if !resp.status().is_success() {
        let text = resp.text().unwrap_or_default();
        eprintln!("error: {}", text);
        std::process::exit(1);
    }

    eprintln!("Secret '{}' stored.", label);
}

fn run_get(
    client: &reqwest::blocking::Client,
    api_url: &str,
    label: &str,
    output: Option<PathBuf>,
) {
    let auth = get_auth(client, api_url);
    let secrets = fetch_and_decrypt_secrets(client, &auth);

    let found = secrets
        .iter()
        .find(|(_, blob, _)| blob.display_name() == label);
    match found {
        Some((_, blob, _)) => {
            if let Some(path) = output {
                std::fs::write(&path, blob.secret_value().unwrap_or("")).unwrap_or_else(|e| {
                    eprintln!("error writing {}: {}", path.display(), e);
                    std::process::exit(1);
                });
                eprintln!("Written to {}", path.display());
            } else {
                print!("{}", blob.secret_value().unwrap_or(""));
            }
        }
        None => {
            eprintln!("error: secret '{}' not found", label);
            std::process::exit(1);
        }
    }
}

fn run_ls(client: &reqwest::blocking::Client, api_url: &str, prefix: Option<&str>) {
    let auth = get_auth(client, api_url);
    let secrets = fetch_and_decrypt_secrets(client, &auth);

    let filtered: Vec<_> = secrets
        .iter()
        .filter(|(_, blob, _)| match prefix {
            Some(p) => blob.display_name().starts_with(p),
            None => true,
        })
        .collect();

    if filtered.is_empty() {
        eprintln!("No secrets found.");
        return;
    }

    for (_, blob, _) in &filtered {
        if blob.is_file() {
            println!("[file] {}", blob.display_name());
        } else {
            println!("{}", blob.display_name());
        }
    }
}

fn run_rm(client: &reqwest::blocking::Client, api_url: &str, label: &str) {
    let auth = get_auth(client, api_url);
    let secrets = fetch_and_decrypt_secrets(client, &auth);

    let found = secrets
        .iter()
        .find(|(_, blob, _)| blob.display_name() == label);
    match found {
        Some((item_id, _, _)) => {
            let resp = client
                .delete(format!("{}/items/{}", auth.api_url(), item_id))
                .header("Authorization", format!("Bearer {}", auth.jwt()))
                .send()
                .unwrap_or_else(|e| {
                    eprintln!("error: {}", e);
                    std::process::exit(1);
                });

            if !resp.status().is_success() {
                let text = resp.text().unwrap_or_default();
                eprintln!("error: {}", text);
                std::process::exit(1);
            }

            eprintln!("Secret '{}' deleted.", label);
        }
        None => {
            eprintln!("error: secret '{}' not found", label);
            std::process::exit(1);
        }
    }
}

fn run_file_put(
    client: &reqwest::blocking::Client,
    api_url: &str,
    label: &str,
    file_path: &std::path::Path,
) {
    let auth = get_auth(client, api_url);

    if !file_path.exists() {
        eprintln!("error: file not found: {}", file_path.display());
        std::process::exit(1);
    }

    let file_data = std::fs::read(file_path).unwrap_or_else(|e| {
        eprintln!("error reading {}: {}", file_path.display(), e);
        std::process::exit(1);
    });

    let file_name = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file")
        .to_string();

    let mime_type = mime_guess::from_path(file_path)
        .first_or_octet_stream()
        .to_string();

    let master_key = match &auth {
        AuthContext::Full { master_key, .. } => master_key,
        AuthContext::Scoped { .. } => {
            eprintln!("error: scoped API keys cannot create items");
            std::process::exit(1);
        }
    };

    let user_id = load_session().map(|s| s.user_id).unwrap_or_default();
    let blob_aad = format!("item:{}", user_id);
    let wrap_aad_str = format!("wrap:{}", user_id);
    let enc_key = derive_subkey(master_key, b"vault-enc").unwrap_or_else(|e| {
        eprintln!("error: {}", e);
        std::process::exit(1);
    });

    // Encrypt file data with its own key (pad to hide size, same AAD as web UI: "item:{user_id}")
    eprintln!("Encrypting {}...", file_name);
    let mut file_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut file_key);

    let padded = pad_plaintext(&file_data);
    let enc_file = vault_core::crypto::encrypt_item_v1(&file_key, &padded, blob_aad.as_bytes())
        .unwrap_or_else(|e| {
            eprintln!("error encrypting file: {}", e);
            std::process::exit(1);
        });
    let mut file_blob = Vec::with_capacity(1 + 24 + enc_file.ciphertext.len());
    file_blob.push(0x01);
    file_blob.extend_from_slice(&enc_file.nonce);
    file_blob.extend_from_slice(&enc_file.ciphertext);

    // Wrap file key with enc_subkey (stored inside envelope)
    let file_wrapped =
        vault_core::crypto::encrypt_item_v1(&enc_key, &file_key, wrap_aad_str.as_bytes())
            .unwrap_or_else(|e| {
                eprintln!("error: {}", e);
                std::process::exit(1);
            });

    // Build metadata envelope (matches web UI format)
    let blob = SecretBlob {
        name: label.to_string(),
        content: None,
        label: None,
        item_type: Some("document".into()),
        value: None,
        filename: Some(file_name.clone()),
        mime_type: Some(mime_type),
        file_size: Some(file_data.len() as u64),
        file_wrapped_key: Some(file_wrapped.ciphertext.to_vec()),
        file_nonce: Some(file_wrapped.nonce.to_vec()),
    };
    let blob_json = serde_json::to_vec(&blob).expect("serialize blob");

    // Encrypt envelope with its own key
    let mut envelope_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut envelope_key);

    let padded_envelope = pad_plaintext(&blob_json);
    let enc_blob =
        vault_core::crypto::encrypt_item_v1(&envelope_key, &padded_envelope, blob_aad.as_bytes())
            .unwrap_or_else(|e| {
                eprintln!("error encrypting envelope: {}", e);
                std::process::exit(1);
            });
    let mut blob_data = Vec::with_capacity(1 + 24 + enc_blob.ciphertext.len());
    blob_data.push(0x01);
    blob_data.extend_from_slice(&enc_blob.nonce);
    blob_data.extend_from_slice(&enc_blob.ciphertext);
    let envelope_b64 = STANDARD.encode(&blob_data);
    let file_blob_len = file_blob.len();

    // Get presigned upload URL
    eprintln!("Uploading ({} bytes)...", file_blob_len);
    let url_resp: serde_json::Value = client
        .post(format!("{}/items/upload-url", auth.api_url()))
        .header("Authorization", format!("Bearer {}", auth.jwt()))
        .json(&serde_json::json!({ "size_bytes": file_blob_len }))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: failed to get upload URL: {}", e);
            std::process::exit(1);
        })
        .json()
        .unwrap_or_else(|e| {
            eprintln!("error: invalid upload-url response: {}", e);
            std::process::exit(1);
        });

    let upload_url = url_resp["upload_url"].as_str().unwrap_or_else(|| {
        eprintln!("error: missing upload_url in response");
        std::process::exit(1);
    });
    let s3_key = url_resp["s3_key"].as_str().unwrap_or_else(|| {
        eprintln!("error: missing s3_key in response");
        std::process::exit(1);
    });

    // Upload file blob to S3 (with API proxy fallback)
    let proxy_upload = url_resp["proxy_upload"].as_bool().unwrap_or(false);
    let upload_result = client.put(upload_url).body(file_blob.clone()).send();
    let needs_fallback = match &upload_result {
        Err(_) => true,
        Ok(resp) => !resp.status().is_success() && proxy_upload,
    };

    if needs_fallback && proxy_upload {
        eprintln!("Direct upload failed, falling back to API proxy...");
        let proxy_resp = client
            .put(format!("{}/items/upload/{}", auth.api_url(), s3_key))
            .header("Authorization", format!("Bearer {}", auth.jwt()))
            .body(file_blob)
            .send()
            .unwrap_or_else(|e| {
                eprintln!("error: proxy upload failed: {}", e);
                std::process::exit(1);
            });
        if !proxy_resp.status().is_success() {
            eprintln!("error: proxy upload failed ({})", proxy_resp.status());
            std::process::exit(1);
        }
    } else {
        let put_resp = upload_result.unwrap_or_else(|e| {
            eprintln!("error: upload failed: {}", e);
            std::process::exit(1);
        });
        if !put_resp.status().is_success() {
            eprintln!("error: upload failed ({})", put_resp.status());
            std::process::exit(1);
        }
    }

    // Wrap envelope key with encryption subkey
    let wrapped =
        vault_core::crypto::encrypt_item_v1(&enc_key, &envelope_key, wrap_aad_str.as_bytes())
            .unwrap_or_else(|e| {
                eprintln!("error: {}", e);
                std::process::exit(1);
            });

    // Create item with envelope inline + file blob reference
    let resp = client
        .post(format!("{}/items", auth.api_url()))
        .header("Authorization", format!("Bearer {}", auth.jwt()))
        .json(&serde_json::json!({
            "encrypted_blob": envelope_b64,
            "wrapped_key": wrapped.ciphertext,
            "nonce": wrapped.nonce.to_vec(),
            "item_type": "encrypted",
            "file_blob_key": s3_key,
            "size_bytes": file_blob_len,
        }))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

    if !resp.status().is_success() {
        let text = resp.text().unwrap_or_default();
        eprintln!("error: {}", text);
        std::process::exit(1);
    }

    eprintln!("File '{}' stored as '{}'.", file_name, label);
}

fn run_file_get(
    client: &reqwest::blocking::Client,
    api_url: &str,
    label: &str,
    output: Option<PathBuf>,
) {
    let auth = get_auth(client, api_url);

    // Find the file item by listing and decrypting envelopes
    let (jwt, enc_key, user_id) = match &auth {
        AuthContext::Full {
            jwt,
            master_key,
            api_url: _,
        } => {
            let user_id = load_session().map(|s| s.user_id).unwrap_or_default();
            let enc_key = derive_subkey(master_key, b"vault-enc").unwrap_or_else(|e| {
                eprintln!("error: {}", e);
                std::process::exit(1);
            });
            (jwt.clone(), enc_key, user_id)
        }
        AuthContext::Scoped { .. } => {
            eprintln!("error: file get is not supported with scoped API keys");
            std::process::exit(1);
        }
    };

    let resp = client
        .get(format!("{}/items", auth.api_url()))
        .header("Authorization", format!("Bearer {}", jwt))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

    if !resp.status().is_success() {
        let text = resp.text().unwrap_or_default();
        eprintln!("error: {}", text);
        std::process::exit(1);
    }

    let items: Vec<serde_json::Value> = resp.json().expect("invalid JSON");

    let wrap_aad = if user_id.is_empty() {
        Vec::new()
    } else {
        format!("wrap:{}", user_id).into_bytes()
    };
    let blob_aad = if user_id.is_empty() {
        Vec::new()
    } else {
        format!("item:{}", user_id).into_bytes()
    };

    // Find matching file item and keep its item_key
    let mut found: Option<(String, SecretBlob, [u8; 32])> = None;
    for item in &items {
        let item_id = item["id"].as_str().unwrap_or("").to_string();
        let wrapped_key = json_to_bytes(&item["wrapped_key"]);
        let nonce = json_to_bytes(&item["nonce"]);
        if wrapped_key.is_empty() || nonce.is_empty() {
            continue;
        }

        let item_key_plain = match vault_core::crypto::decrypt_item_auto(
            &enc_key,
            &wrapped_key,
            &nonce,
            &wrap_aad,
        ) {
            Ok(k) => k,
            Err(_) => continue,
        };
        if item_key_plain.len() != 32 {
            continue;
        }
        let mut item_key = [0u8; 32];
        item_key.copy_from_slice(&item_key_plain);

        // Decrypt the inline envelope
        let enc_blob_str = item["encrypted_blob"].as_str().unwrap_or("");
        if enc_blob_str.is_empty() {
            continue;
        }
        let blob_data = STANDARD.decode(enc_blob_str).unwrap_or_default();
        if blob_data.len() < 25 {
            continue;
        }

        let decrypted = if blob_data[0] == 0x01 && blob_data.len() > 25 {
            let n = &blob_data[1..25];
            let ct = &blob_data[25..];
            vault_core::crypto::decrypt_item_auto(&item_key, ct, n, &blob_aad)
                .or_else(|_| decrypt_item(&item_key, &blob_data[24..], &blob_data[..24]))
                .ok()
        } else {
            decrypt_item(&item_key, &blob_data[24..], &blob_data[..24]).ok()
        };

        let Some(decrypted) = decrypted else {
            continue;
        };

        // Envelope may be padded (web UI pads it)
        let envelope_bytes = unpad(&decrypted);

        let Ok(blob) = serde_json::from_slice::<SecretBlob>(envelope_bytes) else {
            continue;
        };

        if blob.is_file() && blob.display_name() == label {
            found = Some((item_id, blob, item_key));
            break;
        }
    }

    let (item_id, blob, _envelope_key) = match found {
        Some(f) => f,
        None => {
            eprintln!("error: file '{}' not found", label);
            std::process::exit(1);
        }
    };

    // Unwrap the file key from the envelope (or fall back to the envelope key)
    let file_key = if let (Some(fwk), Some(fn_)) = (&blob.file_wrapped_key, &blob.file_nonce) {
        let fk_plain = vault_core::crypto::decrypt_item_auto(&enc_key, fwk, fn_, &wrap_aad)
            .unwrap_or_else(|e| {
                eprintln!("error unwrapping file key: {}", e);
                std::process::exit(1);
            });
        if fk_plain.len() != 32 {
            eprintln!("error: invalid file key length");
            std::process::exit(1);
        }
        let mut fk = [0u8; 32];
        fk.copy_from_slice(&fk_plain);
        fk
    } else {
        _envelope_key
    };

    // Download the encrypted file blob
    eprintln!("Downloading...");
    let blob_resp = client
        .get(format!("{}/items/{}/blob", auth.api_url(), item_id))
        .header("Authorization", format!("Bearer {}", jwt))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

    if !blob_resp.status().is_success() {
        let text = blob_resp.text().unwrap_or_default();
        eprintln!("error downloading file: {}", text);
        std::process::exit(1);
    }

    let raw = blob_resp.bytes().unwrap_or_default().to_vec();

    // Try base64 decode (S3 may return base64-encoded data)
    let file_blob_data = STANDARD.decode(&raw).unwrap_or(raw);

    if file_blob_data.len() < 25 {
        eprintln!("error: file blob too small");
        std::process::exit(1);
    }

    // Decrypt file blob (V1 format, AAD = "item:{user_id}" matching web UI)
    let decrypted = if file_blob_data[0] == 0x01 && file_blob_data.len() > 25 {
        let n = &file_blob_data[1..25];
        let ct = &file_blob_data[25..];
        vault_core::crypto::decrypt_item_auto(&file_key, ct, n, &blob_aad)
    } else {
        decrypt_item(&file_key, &file_blob_data[24..], &file_blob_data[..24])
    }
    .unwrap_or_else(|e| {
        eprintln!("error decrypting file: {}", e);
        std::process::exit(1);
    });

    // Unpad to get original file bytes
    let file_bytes = unpad(&decrypted);

    // Determine output path
    let out_path =
        output.unwrap_or_else(|| PathBuf::from(blob.filename.as_deref().unwrap_or(label)));

    std::fs::write(&out_path, file_bytes).unwrap_or_else(|e| {
        eprintln!("error writing {}: {}", out_path.display(), e);
        std::process::exit(1);
    });

    eprintln!("File '{}' saved to {}", label, out_path.display());
}

fn parse_dotenv(content: &str) -> Vec<(String, String)> {
    let mut vars = Vec::new();
    let mut lines = content.lines().peekable();

    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Strip optional "export " prefix
        let trimmed = trimmed.strip_prefix("export ").unwrap_or(trimmed);

        let Some(eq_pos) = trimmed.find('=') else {
            eprintln!("warning: skipping malformed line: {}", trimmed);
            continue;
        };

        let key = trimmed[..eq_pos].trim().to_string();
        let raw_value = &trimmed[eq_pos + 1..];

        let value = if let Some(dq_inner) = raw_value.strip_prefix('"') {
            // Double-quoted: handle escapes, may span multiple lines
            let mut buf = dq_inner.to_string();
            while !buf.ends_with('"') || buf.ends_with("\\\"") {
                if let Some(next_line) = lines.next() {
                    buf.push('\n');
                    buf.push_str(next_line);
                } else {
                    break;
                }
            }
            // Remove trailing quote
            if buf.ends_with('"') {
                buf.pop();
            }
            // Process escapes
            buf.replace("\\n", "\n")
                .replace("\\\"", "\"")
                .replace("\\\\", "\\")
        } else if let Some(sq_inner) = raw_value.strip_prefix('\'') {
            // Single-quoted: literal, no escapes
            let inner = sq_inner.strip_suffix('\'').unwrap_or(sq_inner);
            inner.to_string()
        } else {
            // Unquoted: strip inline comments
            let value = if let Some(comment_pos) = raw_value.find(" #") {
                &raw_value[..comment_pos]
            } else {
                raw_value
            };
            value.trim().to_string()
        };

        if key.is_empty() {
            continue;
        }
        vars.push((key, value));
    }

    vars
}

fn find_envfile<'a>(
    secrets: &'a [(String, SecretBlob, String)],
    label: &str,
) -> Option<&'a (String, SecretBlob, String)> {
    secrets.iter().find(|(_, blob, _)| {
        blob.display_name() == label && blob.item_type.as_deref() == Some("envfile")
    })
}

fn run_env_push(client: &reqwest::blocking::Client, api_url: &str, label: &str, file: &str) {
    let content = if file == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .unwrap_or_else(|e| {
                eprintln!("error reading stdin: {}", e);
                std::process::exit(1);
            });
        buf
    } else {
        std::fs::read_to_string(file).unwrap_or_else(|e| {
            eprintln!("error reading {}: {}", file, e);
            std::process::exit(1);
        })
    };

    // Validate the .env content parses correctly
    let vars = parse_dotenv(&content);
    eprintln!(
        "Parsed {} variables from {}",
        vars.len(),
        if file == "-" { "stdin" } else { file }
    );

    let auth = get_auth(client, api_url);

    // Check if envfile already exists, delete it first
    let secrets = fetch_and_decrypt_secrets(client, &auth);
    if let Some((item_id, _, _)) = find_envfile(&secrets, label) {
        let resp = client
            .delete(format!("{}/items/{}", auth.api_url(), item_id))
            .header("Authorization", format!("Bearer {}", auth.jwt()))
            .send()
            .unwrap_or_else(|e| {
                eprintln!("error: {}", e);
                std::process::exit(1);
            });
        if !resp.status().is_success() {
            let text = resp.text().unwrap_or_default();
            eprintln!("error deleting old envfile: {}", text);
            std::process::exit(1);
        }
    }

    // Create the envfile item
    let blob = SecretBlob {
        name: label.to_string(),
        content: Some(content),
        label: None,
        item_type: Some("envfile".to_string()),
        value: None,
        filename: None,
        mime_type: None,
        file_size: None,
        file_wrapped_key: None,
        file_nonce: None,
    };
    let blob_json = serde_json::to_vec(&blob).expect("serialize blob");

    let mut item_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut item_key);

    let enc_blob = encrypt_item(&item_key, &blob_json).unwrap_or_else(|e| {
        eprintln!("error encrypting: {}", e);
        std::process::exit(1);
    });

    let mut blob_data = Vec::with_capacity(24 + enc_blob.ciphertext.len());
    blob_data.extend_from_slice(&enc_blob.nonce);
    blob_data.extend_from_slice(&enc_blob.ciphertext);
    let blob_b64 = STANDARD.encode(&blob_data);

    let master_key = match &auth {
        AuthContext::Full { master_key, .. } => master_key,
        AuthContext::Scoped { .. } => {
            eprintln!("error: scoped API keys cannot create items");
            std::process::exit(1);
        }
    };
    let enc_key = derive_subkey(master_key, b"vault-enc").unwrap_or_else(|e| {
        eprintln!("error: {}", e);
        std::process::exit(1);
    });
    let wrapped = encrypt_item(&enc_key, &item_key).unwrap_or_else(|e| {
        eprintln!("error: {}", e);
        std::process::exit(1);
    });

    let resp = client
        .post(format!("{}/items", auth.api_url()))
        .header("Authorization", format!("Bearer {}", auth.jwt()))
        .json(&serde_json::json!({
            "encrypted_blob": blob_b64,
            "wrapped_key": wrapped.ciphertext,
            "nonce": wrapped.nonce.to_vec(),
            "item_type": "encrypted",
        }))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

    if !resp.status().is_success() {
        let text = resp.text().unwrap_or_default();
        eprintln!("error: {}", text);
        std::process::exit(1);
    }

    eprintln!("Env file '{}' stored ({} variables).", label, vars.len());
}

fn run_env_pull(
    client: &reqwest::blocking::Client,
    api_url: &str,
    label: &str,
    output: Option<PathBuf>,
) {
    let auth = get_auth(client, api_url);
    let secrets = fetch_and_decrypt_secrets(client, &auth);

    match find_envfile(&secrets, label) {
        Some((_, blob, _)) => {
            if let Some(path) = output {
                std::fs::write(&path, blob.secret_value().unwrap_or("")).unwrap_or_else(|e| {
                    eprintln!("error writing {}: {}", path.display(), e);
                    std::process::exit(1);
                });
                eprintln!("Written to {}", path.display());
            } else {
                print!("{}", blob.secret_value().unwrap_or(""));
            }
        }
        None => {
            eprintln!("error: env file '{}' not found", label);
            std::process::exit(1);
        }
    }
}

fn run_env_run(client: &reqwest::blocking::Client, api_url: &str, label: &str, cmd: &[String]) {
    if cmd.is_empty() {
        eprintln!("error: no command specified");
        std::process::exit(1);
    }

    let auth = get_auth(client, api_url);
    let secrets = fetch_and_decrypt_secrets(client, &auth);

    let (_, blob, _) = match find_envfile(&secrets, label) {
        Some(entry) => entry,
        None => {
            eprintln!("error: env file '{}' not found", label);
            std::process::exit(1);
        }
    };

    let env_vars = parse_dotenv(blob.secret_value().unwrap_or(""));

    let mut command = std::process::Command::new(&cmd[0]);
    command.args(&cmd[1..]);
    for (k, v) in &env_vars {
        command.env(k, v);
    }

    let status = command.status().unwrap_or_else(|e| {
        eprintln!("error: failed to run command: {}", e);
        std::process::exit(1);
    });

    std::process::exit(status.code().unwrap_or(1));
}

fn run_env_export(client: &reqwest::blocking::Client, api_url: &str, label: &str) {
    let auth = get_auth(client, api_url);
    let secrets = fetch_and_decrypt_secrets(client, &auth);

    let (_, blob, _) = match find_envfile(&secrets, label) {
        Some(entry) => entry,
        None => {
            eprintln!("error: env file '{}' not found", label);
            std::process::exit(1);
        }
    };

    let env_vars = parse_dotenv(blob.secret_value().unwrap_or(""));

    for (k, v) in &env_vars {
        // Shell-escape the value: wrap in single quotes, escape existing single quotes
        let escaped = v.replace('\'', "'\\''");
        println!("export {}='{}'", k, escaped);
    }
}

fn run_env(client: &reqwest::blocking::Client, api_url: &str, prefix: &str, cmd: &[String]) {
    if cmd.is_empty() {
        eprintln!("error: no command specified");
        std::process::exit(1);
    }

    let auth = get_auth(client, api_url);
    let secrets = fetch_and_decrypt_secrets(client, &auth);

    let matching: Vec<_> = secrets
        .iter()
        .filter(|(_, blob, _)| blob.display_name().starts_with(prefix))
        .collect();

    let mut env_vars: Vec<(String, String)> = Vec::new();
    for (_, blob, _) in &matching {
        let name = blob.display_name()[prefix.len()..]
            .to_uppercase()
            .replace(['/', '-'], "_");
        if name.is_empty() {
            continue;
        }
        env_vars.push((name, blob.secret_value().unwrap_or("").to_string()));
    }

    let mut command = std::process::Command::new(&cmd[0]);
    command.args(&cmd[1..]);
    for (k, v) in &env_vars {
        command.env(k, v);
    }

    let status = command.status().unwrap_or_else(|e| {
        eprintln!("error: failed to run command: {}", e);
        std::process::exit(1);
    });

    std::process::exit(status.code().unwrap_or(1));
}

// --- Existing commands ---

fn run_notarize(
    client: &reqwest::blocking::Client,
    api_url: &str,
    token: &str,
    input: &str,
    item_id: Option<&str>,
    output: Option<PathBuf>,
) {
    // Determine if input is a hex hash or a file path
    let content_hash = if input.len() == 64 && input.chars().all(|c| c.is_ascii_hexdigit()) {
        input.to_string()
    } else {
        let path = PathBuf::from(input);
        if !path.exists() {
            eprintln!("error: '{}' is not a file or a 64-char hex hash", input);
            std::process::exit(1);
        }
        eprintln!("Hashing {}...", input);
        let data = std::fs::read(&path).unwrap_or_else(|e| {
            eprintln!("error reading {}: {}", input, e);
            std::process::exit(1);
        });
        let hash = Sha256::digest(&data);
        hex::encode(hash)
    };

    eprintln!("Content hash: {}", content_hash);

    let mut body = serde_json::json!({ "content_hash": content_hash });
    if let Some(id) = item_id {
        body["item_id"] = serde_json::Value::String(id.to_string());
    }

    let resp = client
        .post(format!("{}/notarizations", api_url))
        .header("Authorization", format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .expect("request failed");

    if !resp.status().is_success() {
        let text = resp.text().unwrap_or_default();
        eprintln!("error: notarization failed: {}", text);
        std::process::exit(1);
    }

    let result: serde_json::Value = resp.json().expect("invalid JSON");
    let notarization_id = result["id"].as_str().unwrap();
    eprintln!("Notarization created: {}", notarization_id);

    // Fetch certificate
    let cert_resp = client
        .get(format!(
            "{}/notarizations/{}/certificate",
            api_url, notarization_id
        ))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .expect("certificate request failed");

    if !cert_resp.status().is_success() {
        eprintln!("warning: could not fetch certificate");
        return;
    }

    let cert: serde_json::Value = cert_resp.json().expect("invalid certificate JSON");
    let cert_json = serde_json::to_string_pretty(&cert).unwrap();

    let out_path = output
        .unwrap_or_else(|| PathBuf::from(format!("notarization-{}.json", &notarization_id[..8])));
    std::fs::write(&out_path, &cert_json).unwrap_or_else(|e| {
        eprintln!("error writing {}: {}", out_path.display(), e);
        std::process::exit(1);
    });
    eprintln!("Certificate saved to {}", out_path.display());
}

fn run_verify(certificate_path: &std::path::Path, document: Option<&std::path::Path>) {
    let cert_json = std::fs::read_to_string(certificate_path).unwrap_or_else(|e| {
        eprintln!("error reading {}: {}", certificate_path.display(), e);
        std::process::exit(1);
    });
    let cert: serde_json::Value = serde_json::from_str(&cert_json).unwrap_or_else(|e| {
        eprintln!("error parsing certificate: {}", e);
        std::process::exit(1);
    });

    // 1. Verify document hash if provided
    if let Some(doc_path) = document {
        let data = std::fs::read(doc_path).unwrap_or_else(|e| {
            eprintln!("error reading {}: {}", doc_path.display(), e);
            std::process::exit(1);
        });
        let hash = Sha256::digest(&data);
        let hash_hex = hex::encode(hash);
        let cert_hash = cert["content_hash"].as_str().unwrap_or("");
        if hash_hex == cert_hash {
            eprintln!("[PASS] Document hash matches certificate");
        } else {
            eprintln!("[FAIL] Document hash mismatch");
            eprintln!("  Document: {}", hash_hex);
            eprintln!("  Certificate: {}", cert_hash);
        }
    }

    // 2. Verify Ed25519 signature
    let content_hash_hex = cert["content_hash"].as_str().unwrap_or("");
    let content_hash = hex::decode(content_hash_hex).unwrap_or_default();
    let tree_root_hex = cert["tree_root"].as_str().unwrap_or("");
    let tree_root = hex::decode(tree_root_hex).unwrap_or_default();
    let timestamp_millis = cert["timestamp_millis"].as_i64().unwrap_or(0);
    let signature_b64 = cert["signature"].as_str().unwrap_or("");
    let signature = STANDARD.decode(signature_b64).unwrap_or_default();
    let signing_key_b64 = cert["signing_key"].as_str().unwrap_or("");
    let signing_key = STANDARD.decode(signing_key_b64).unwrap_or_default();

    if content_hash.len() == 32
        && tree_root.len() == 32
        && signature.len() == 64
        && signing_key.len() == 32
    {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&signing_key);
        let mut ch = [0u8; 32];
        ch.copy_from_slice(&content_hash);
        let mut tr = [0u8; 32];
        tr.copy_from_slice(&tree_root);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&signature);

        if vault_core::crypto::verify_notarization_signature(
            &pk,
            &ch,
            None,
            timestamp_millis,
            &tr,
            &sig,
        ) {
            eprintln!("[PASS] Ed25519 signature valid");
        } else {
            eprintln!("[FAIL] Ed25519 signature invalid");
        }
    } else {
        eprintln!("[FAIL] Invalid certificate field lengths");
    }

    // 3. Print metadata
    eprintln!();
    eprintln!(
        "Notarization ID: {}",
        cert["notarization_id"].as_str().unwrap_or("?")
    );
    eprintln!("Timestamp: {}", cert["timestamp"].as_str().unwrap_or("?"));
    eprintln!(
        "Tree index: {} / size: {}",
        cert["tree_index"], cert["tree_size"]
    );
    if let Some(anchors) = cert["anchors"].as_array() {
        if !anchors.is_empty() {
            eprintln!("Anchors: {} RFC 3161 anchor(s)", anchors.len());
        }
    }
}

fn run_list_notarizations(client: &reqwest::blocking::Client, api_url: &str, token: &str) {
    let resp = client
        .get(format!("{}/notarizations", api_url))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .expect("request failed");

    if !resp.status().is_success() {
        let text = resp.text().unwrap_or_default();
        eprintln!("error: {}", text);
        std::process::exit(1);
    }

    let rows: Vec<serde_json::Value> = resp.json().expect("invalid JSON");
    if rows.is_empty() {
        eprintln!("No notarizations found.");
        return;
    }

    println!("{:<38} {:<26} {:<18}", "ID", "TIMESTAMP", "HASH (short)");
    println!("{}", "-".repeat(82));
    for r in &rows {
        let id = r["id"].as_str().unwrap_or("?");
        let ts = r["timestamp"].as_str().unwrap_or("?");
        let hash = r["content_hash"].as_str().unwrap_or("?");
        let hash_short = if hash.len() > 16 { &hash[..16] } else { hash };
        println!("{:<38} {:<26} {}...", id, ts, hash_short);
    }
}

fn run_drop_download(
    client: &reqwest::blocking::Client,
    api_url: &str,
    key: &str,
    key2: Option<&str>,
    output: Option<PathBuf>,
) {
    let parsed = parse_input(key, key2);

    match parsed {
        ParsedInput::Direct { drop_id, key } => {
            download_drop(client, api_url, &drop_id, &key, output);
        }
        ParsedInput::Mnemonic { mnemonic, drop_id } => {
            let resolved_id = match drop_id {
                Some(id) => id,
                None => {
                    eprintln!("Looking up drop by mnemonic...");
                    let lookup_key = derive_drop_lookup_key(&mnemonic);
                    let url = format!("{}/drops/by-words/{}", api_url, lookup_key);
                    let resp = client.get(&url).send().expect("request failed");
                    if !resp.status().is_success() {
                        eprintln!("error: drop not found (expired or wrong words)");
                        std::process::exit(1);
                    }
                    let drop: serde_json::Value = resp.json().expect("invalid JSON");
                    if drop["claimed"].as_bool() == Some(true) {
                        eprintln!("error: drop already claimed");
                        std::process::exit(1);
                    }
                    drop["id"].as_str().expect("missing drop id").to_string()
                }
            };

            let url = format!("{}/drops/{}", api_url, resolved_id);
            let resp = client.get(&url).send().expect("request failed");
            if !resp.status().is_success() {
                eprintln!("error: drop not found");
                std::process::exit(1);
            }
            let drop_meta: serde_json::Value = resp.json().expect("invalid JSON");
            if drop_meta["claimed"].as_bool() == Some(true) {
                eprintln!("error: drop already claimed");
                std::process::exit(1);
            }

            let wrapped = drop_meta["wrapped_drop_key"]
                .as_array()
                .expect("drop has no wrapped_drop_key (not a mnemonic drop)");
            let wrapped_bytes: Vec<u8> = wrapped
                .iter()
                .map(|v: &serde_json::Value| v.as_u64().unwrap() as u8)
                .collect();

            let version = drop_meta["drop_key_version"].as_i64().unwrap_or(1) as i32;
            eprintln!("Deriving wrapping key (v{})...", version);
            let wrapping_key = derive_drop_wrapping_key(&mnemonic, version);
            let drop_key = unwrap_drop_key(&wrapping_key, &wrapped_bytes);

            download_drop(client, api_url, &resolved_id, &drop_key, output);
        }
    }
}

fn parse_input(key: &str, key2: Option<&str>) -> ParsedInput {
    let input = key.trim();

    if let Some(k2) = key2 {
        let k2 = k2.trim();
        if looks_like_uuid(input) {
            if let Some(key_bytes) = try_decode_base64url(k2) {
                return ParsedInput::Direct {
                    drop_id: input.to_string(),
                    key: key_bytes,
                };
            }
        }
        if looks_like_uuid(k2) {
            if let Some(key_bytes) = try_decode_base64url(input) {
                return ParsedInput::Direct {
                    drop_id: k2.to_string(),
                    key: key_bytes,
                };
            }
        }
        let combined = format!("{} {}", input, k2);
        return parse_input(&combined, None);
    }

    if let Some(caps) = extract_drop_url(input) {
        return ParsedInput::Direct {
            drop_id: caps.0,
            key: caps.1,
        };
    }

    if let Some(slug) = extract_pickup_slug(input) {
        let mnemonic = slug.replace('-', " ");
        return ParsedInput::Mnemonic {
            mnemonic: normalize_mnemonic(&mnemonic),
            drop_id: None,
        };
    }

    if extract_pickup_uuid(input).is_some() {
        eprintln!("error: pickup URL with UUID requires a mnemonic — provide the 12 words instead");
        std::process::exit(1);
    }

    let hyphen_words: Vec<&str> = input.split('-').collect();
    if hyphen_words.len() == 12
        && hyphen_words
            .iter()
            .all(|w| w.chars().all(|c| c.is_ascii_lowercase()))
    {
        return ParsedInput::Mnemonic {
            mnemonic: hyphen_words.join(" "),
            drop_id: None,
        };
    }

    let space_words: Vec<&str> = input.split_whitespace().collect();
    if space_words.len() == 12
        && space_words
            .iter()
            .all(|w| w.chars().all(|c| c.is_ascii_alphabetic()))
    {
        return ParsedInput::Mnemonic {
            mnemonic: normalize_mnemonic(input),
            drop_id: None,
        };
    }

    if looks_like_uuid(input) {
        eprintln!(
            "error: drop UUID provided without a key — provide a base64url key as second argument"
        );
        std::process::exit(1);
    }

    if try_decode_base64url(input).is_some() {
        eprintln!("error: base64url key provided without a drop UUID");
        std::process::exit(1);
    }

    eprintln!("error: could not parse input as a drop URL, BIP39 mnemonic, or UUID + key");
    std::process::exit(1);
}

fn looks_like_uuid(s: &str) -> bool {
    uuid::Uuid::parse_str(s).is_ok()
}

fn try_decode_base64url(s: &str) -> Option<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD.decode(s).ok()?;
    if bytes.len() == 32 {
        Some(bytes.try_into().unwrap())
    } else {
        None
    }
}

fn extract_drop_url(s: &str) -> Option<(String, [u8; 32])> {
    let drop_idx = s.find("/drop/")?;
    let rest = &s[drop_idx + 6..];
    let uuid_end = rest.find('?').unwrap_or(rest.len());
    let uuid_str = &rest[..uuid_end];
    if !looks_like_uuid(uuid_str) {
        return None;
    }
    let key_start = rest.find("key=")?;
    let key_str = &rest[key_start + 4..];
    let key_end = key_str.find('&').unwrap_or(key_str.len());
    let key_str = &key_str[..key_end];
    let key = try_decode_base64url(key_str)?;
    Some((uuid_str.to_string(), key))
}

fn extract_pickup_slug(s: &str) -> Option<String> {
    let idx = s.find("/pickup/")?;
    let rest = &s[idx + 8..];
    let slug = rest
        .split(&['?', '&', '#'][..])
        .next()
        .unwrap_or(rest)
        .trim();
    let words: Vec<&str> = slug.split('-').collect();
    if words.len() == 12
        && words
            .iter()
            .all(|w| w.chars().all(|c| c.is_ascii_lowercase()))
    {
        Some(slug.to_string())
    } else {
        None
    }
}

fn extract_pickup_uuid(s: &str) -> Option<String> {
    let idx = s.find("/pickup/")?;
    let rest = &s[idx + 8..];
    let id = rest
        .split(&['?', '&', '#'][..])
        .next()
        .unwrap_or(rest)
        .trim();
    if looks_like_uuid(id) {
        Some(id.to_string())
    } else {
        None
    }
}

fn download_drop(
    client: &reqwest::blocking::Client,
    api_url: &str,
    drop_id: &str,
    key: &[u8; 32],
    output: Option<PathBuf>,
) {
    eprintln!("Downloading drop {}...", drop_id);
    let url = format!("{}/drops/{}/blob", api_url, drop_id);
    let resp = client.get(&url).send().expect("request failed");
    if !resp.status().is_success() {
        eprintln!("error: failed to download blob ({})", resp.status());
        std::process::exit(1);
    }
    let encrypted = resp.bytes().expect("failed to read body");
    let encrypted = encrypted.as_ref();

    if encrypted.len() < 24 {
        eprintln!("error: blob too short");
        std::process::exit(1);
    }

    let nonce = &encrypted[..24];
    let ciphertext = &encrypted[24..];

    eprintln!("Decrypting...");
    let padded = decrypt_item(key, ciphertext, nonce).unwrap_or_else(|e| {
        eprintln!("error: decryption failed: {}", e);
        std::process::exit(1);
    });

    let plain = unpad(&padded);
    let (filename, file_data) = parse_envelope(plain, drop_id);

    let out_path = output.unwrap_or_else(|| PathBuf::from(&filename));
    std::fs::write(&out_path, file_data).unwrap_or_else(|e| {
        eprintln!("error writing {}: {}", out_path.display(), e);
        std::process::exit(1);
    });
    eprintln!("Saved to {}", out_path.display());
}

fn unpad(data: &[u8]) -> &[u8] {
    if data.len() < 4 {
        return data;
    }
    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if len > data.len() - 4 {
        return data;
    }
    &data[4..4 + len]
}

fn parse_envelope<'a>(data: &'a [u8], drop_id: &str) -> (String, &'a [u8]) {
    if data.len() > 4 {
        let header_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if header_len > 0 && header_len < 10240 && 4 + header_len <= data.len() {
            if let Ok(meta_json) = std::str::from_utf8(&data[4..4 + header_len]) {
                if let Ok(meta) = serde_json::from_str::<serde_json::Value>(meta_json) {
                    let name = meta["name"]
                        .as_str()
                        .unwrap_or(&format!("drop-{}", &drop_id[..8]))
                        .to_string();
                    return (name, &data[4 + header_len..]);
                }
            }
        }
    }
    (format!("drop-{}", &drop_id[..8.min(drop_id.len())]), data)
}

fn normalize_mnemonic(m: &str) -> String {
    m.split_whitespace()
        .map(|w| w.to_lowercase())
        .collect::<Vec<_>>()
        .join(" ")
}

fn derive_drop_lookup_key(mnemonic: &str) -> String {
    let hkdf = Hkdf::<Sha256>::new(Some(b"vault-drop"), mnemonic.as_bytes());
    let mut out = [0u8; 32];
    hkdf.expand(b"lookup", &mut out)
        .expect("HKDF expand failed");
    hex::encode(out)
}

fn derive_drop_wrapping_key(mnemonic: &str, version: i32) -> [u8; 32] {
    let iterations = if version >= 2 { 600_000 } else { 2048 };
    let mut out = [0u8; 32];
    pbkdf2::<Hmac<Sha512>>(mnemonic.as_bytes(), b"vault-drop", iterations, &mut out)
        .expect("PBKDF2 failed");
    out
}

fn wrap_drop_key(wrapping_key: &[u8; 32], drop_key: &[u8; 32]) -> Vec<u8> {
    let enc = encrypt_item(wrapping_key, drop_key).expect("wrap failed");
    let mut out = Vec::with_capacity(24 + enc.ciphertext.len());
    out.extend_from_slice(&enc.nonce);
    out.extend_from_slice(&enc.ciphertext);
    out
}

fn unwrap_drop_key(wrapping_key: &[u8; 32], wrapped: &[u8]) -> [u8; 32] {
    if wrapped.len() < 25 {
        eprintln!("error: wrapped_drop_key too short");
        std::process::exit(1);
    }
    let nonce = &wrapped[..24];
    let ciphertext = &wrapped[24..];
    let plain = decrypt_item(wrapping_key, ciphertext, nonce).unwrap_or_else(|e| {
        eprintln!("error: failed to unwrap drop key (wrong mnemonic?): {}", e);
        std::process::exit(1);
    });
    if plain.len() != 32 {
        eprintln!("error: unwrapped key is {} bytes, expected 32", plain.len());
        std::process::exit(1);
    }
    let bytes: [u8; 32] = plain.as_slice().try_into().unwrap();
    bytes
}

fn padded_size(actual: usize) -> usize {
    let total = 4 + actual;
    if total <= 1024 {
        return 1024;
    }
    if total <= 16384 {
        let mut s = 1024;
        while s < total {
            s *= 2;
        }
        return s;
    }
    if total <= 1_048_576 {
        return total.div_ceil(65536) * 65536;
    }
    if total <= 67_108_864 {
        return total.div_ceil(1_048_576) * 1_048_576;
    }
    total.div_ceil(8_388_608) * 8_388_608
}

fn pad_plaintext(data: &[u8]) -> Vec<u8> {
    let target = padded_size(data.len());
    let mut result = vec![0u8; target];
    let len = data.len() as u32;
    result[..4].copy_from_slice(&len.to_be_bytes());
    result[4..4 + data.len()].copy_from_slice(data);
    // Fill padding with random bytes
    if target > 4 + data.len() {
        rand::rngs::OsRng.fill_bytes(&mut result[4 + data.len()..]);
    }
    result
}

fn generate_bip39_mnemonic() -> String {
    use bip39::Mnemonic;
    let mut entropy = [0u8; 16]; // 128 bits → 12 words
    rand::rngs::OsRng.fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy(&entropy).expect("mnemonic generation failed");
    mnemonic.to_string()
}

fn run_drop_upload(client: &reqwest::blocking::Client, api_url: &str, file_path: &std::path::Path) {
    if !file_path.exists() {
        eprintln!("error: file not found: {}", file_path.display());
        std::process::exit(1);
    }

    let file_data = std::fs::read(file_path).unwrap_or_else(|e| {
        eprintln!("error reading {}: {}", file_path.display(), e);
        std::process::exit(1);
    });

    let file_name = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file")
        .to_string();

    let mime_type = mime_guess::from_path(file_path)
        .first_or_octet_stream()
        .to_string();

    // Build envelope: [4-byte header_len][JSON metadata][file bytes]
    let meta = serde_json::json!({
        "name": file_name,
        "type": mime_type,
        "size": file_data.len(),
    });
    let meta_bytes = meta.to_string().into_bytes();
    let header_len = meta_bytes.len() as u32;

    let mut envelope = Vec::with_capacity(4 + meta_bytes.len() + file_data.len());
    envelope.extend_from_slice(&header_len.to_be_bytes());
    envelope.extend_from_slice(&meta_bytes);
    envelope.extend_from_slice(&file_data);

    // Pad plaintext to hide exact file size
    let padded = pad_plaintext(&envelope);

    // Generate random drop key and encrypt
    eprintln!("Encrypting {}...", file_name);
    let mut drop_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut drop_key);

    let enc = encrypt_item(&drop_key, &padded).expect("encryption failed");

    // Build blob: nonce(24) + ciphertext
    let mut blob = Vec::with_capacity(24 + enc.ciphertext.len());
    blob.extend_from_slice(&enc.nonce);
    blob.extend_from_slice(&enc.ciphertext);

    // Generate BIP39 mnemonic and derive keys
    let mnemonic = generate_bip39_mnemonic();
    let lookup_key = derive_drop_lookup_key(&mnemonic);

    eprintln!("Deriving wrapping key...");
    let wrapping_key = derive_drop_wrapping_key(&mnemonic, 2);
    let wrapped_drop_key = wrap_drop_key(&wrapping_key, &drop_key);

    // Get presigned upload URL
    eprintln!("Uploading ({} bytes)...", blob.len());
    let url_resp: serde_json::Value = client
        .post(format!("{}/drops/upload-url", api_url))
        .json(&serde_json::json!({ "size_bytes": blob.len() }))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: failed to get upload URL: {}", e);
            std::process::exit(1);
        })
        .json()
        .unwrap_or_else(|e| {
            eprintln!("error: invalid upload-url response: {}", e);
            std::process::exit(1);
        });

    let upload_url = url_resp["upload_url"].as_str().unwrap_or_else(|| {
        eprintln!("error: missing upload_url in response");
        std::process::exit(1);
    });
    let s3_key = url_resp["s3_key"].as_str().unwrap_or_else(|| {
        eprintln!("error: missing s3_key in response");
        std::process::exit(1);
    });

    // Upload blob to S3 (with API proxy fallback)
    let proxy_upload = url_resp["proxy_upload"].as_bool().unwrap_or(false);
    let upload_result = client.put(upload_url).body(blob.clone()).send();
    let needs_fallback = match &upload_result {
        Err(_) => true,
        Ok(resp) => !resp.status().is_success() && proxy_upload,
    };

    if needs_fallback && proxy_upload {
        eprintln!("Direct upload failed, falling back to API proxy...");
        let proxy_resp = client
            .put(format!("{}/drops/upload/{}", api_url, s3_key))
            .body(blob.clone())
            .send()
            .unwrap_or_else(|e| {
                eprintln!("error: proxy upload failed: {}", e);
                std::process::exit(1);
            });
        if !proxy_resp.status().is_success() {
            eprintln!("error: proxy upload failed ({})", proxy_resp.status());
            std::process::exit(1);
        }
    } else {
        let put_resp = upload_result.unwrap_or_else(|e| {
            eprintln!("error: upload failed: {}", e);
            std::process::exit(1);
        });
        if !put_resp.status().is_success() {
            eprintln!("error: upload failed ({})", put_resp.status());
            std::process::exit(1);
        }
    }

    // Create drop record
    let nonce_array: Vec<u8> = enc.nonce.to_vec();
    let wrapped_array: Vec<u8> = wrapped_drop_key;

    let drop_resp: serde_json::Value = client
        .post(format!("{}/drops", api_url))
        .json(&serde_json::json!({
            "s3_key": s3_key,
            "size_bytes": blob.len(),
            "nonce": nonce_array,
            "wrapped_drop_key": wrapped_array,
            "lookup_key": lookup_key,
            "drop_key_version": 2,
        }))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: failed to create drop: {}", e);
            std::process::exit(1);
        })
        .json()
        .unwrap_or_else(|e| {
            eprintln!("error: invalid drop response: {}", e);
            std::process::exit(1);
        });

    let drop_id = drop_resp["id"].as_str().unwrap_or("?");
    let expires_at = drop_resp["expires_at"].as_str().unwrap_or("?");

    // Build pickup URL with mnemonic slug
    let slug = mnemonic.split_whitespace().collect::<Vec<_>>().join("-");
    let pickup_url = format!("{}/pickup/{}", api_url.trim_end_matches('/'), slug);

    eprintln!();
    eprintln!("Drop created successfully!");
    eprintln!("Drop ID:    {}", drop_id);
    eprintln!("Expires at: {}", expires_at);
    eprintln!();
    eprintln!("Pickup URL: {}", pickup_url);
    eprintln!();
    eprintln!("Passphrase (12 words):");
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    for (i, word) in words.iter().enumerate() {
        eprint!("  {:>2}. {:<12}", i + 1, word);
        if (i + 1) % 4 == 0 {
            eprintln!();
        }
    }
    eprintln!();
    eprintln!("Share the pickup URL or the 12 words with the recipient.");
    eprintln!("The passphrase is embedded in the URL — sharing just the URL is enough.");
}
