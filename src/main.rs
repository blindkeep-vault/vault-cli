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
    decrypt_item, derive_api_key_keys, derive_master_key, derive_subkey, encrypt_item,
    generate_x25519_keypair, unwrap_key, unwrap_master_key, wrap_key_for_recipient,
    wrap_master_key, MasterKey,
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
        default_value = "https://blindkeep.com",
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
    // Priority 2: Session file
    if let Some(session) = load_session() {
        let password = prompt_password("Password: ");
        let master_key = derive_master_key(password.as_bytes(), &session.client_salt)
            .unwrap_or_else(|e| {
                eprintln!("error deriving key: {}", e);
                std::process::exit(1);
            });
        return AuthContext::Full {
            jwt: session.jwt,
            master_key,
            api_url: session.api_url,
        };
    }
    eprintln!("error: not logged in. Run `vault-cli login` or set VAULT_API_KEY");
    std::process::exit(1);
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
    let master_key = derive_master_key(password.as_bytes(), &client_salt).unwrap_or_else(|e| {
        eprintln!("error: key derivation failed: {}", e);
        std::process::exit(1);
    });

    let auth_key = derive_subkey(&master_key, b"auth").unwrap_or_else(|e| {
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

    save_session(&Session {
        api_url: api_url.to_string(),
        jwt,
        email: email.clone(),
        user_id,
        client_salt,
    });

    eprintln!("Logged in as {}", email);
}

fn run_logout() {
    clear_session();
    eprintln!("Logged out.");
}

fn run_status(api_url: &str) {
    if std::env::var("VAULT_API_KEY").is_ok() {
        eprintln!("Auth: VAULT_API_KEY environment variable set");
        return;
    }
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
    if let Some(days) = s.strip_suffix('d') {
        chrono::Duration::days(days.parse().expect("invalid number of days"))
    } else if let Some(years) = s.strip_suffix('y') {
        chrono::Duration::days(years.parse::<i64>().expect("invalid number of years") * 365)
    } else {
        eprintln!(
            "error: invalid expiry format '{}' (use e.g. '30d' or '1y')",
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
        "{:<38} {:<20} {:<14} {:<10} {}",
        "ID", "NAME", "PREFIX", "SCOPE", "LAST USED"
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
        .find(|(_, blob, _)| blob.label == label)
        .unwrap_or_else(|| {
            eprintln!("error: secret '{}' not found", label);
            std::process::exit(1);
        });

    // Unwrap the item key using master key
    let mk = match &auth {
        AuthContext::Full { master_key, .. } => master_key,
        _ => unreachable!(),
    };
    let enc_key = derive_subkey(mk, b"encrypt").unwrap_or_else(|e| {
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

    println!("{:<38} {:<38} {}", "GRANT ID", "ITEM ID", "CREATED");
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
        .find(|(_, blob, _)| blob.label == label)
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

// --- Secret CRUD ---

/// The encrypted blob JSON format for CLI-created secrets.
#[derive(serde::Serialize, serde::Deserialize)]
struct SecretBlob {
    label: String,
    #[serde(rename = "type")]
    item_type: String,
    value: String,
}

fn decrypt_item_blob(
    client: &reqwest::blocking::Client,
    api_url: &str,
    jwt: &str,
    item_id: &str,
    item_key: &[u8; 32],
) -> Option<SecretBlob> {
    let blob_resp = client
        .get(format!("{}/items/{}/blob", api_url, item_id))
        .header("Authorization", format!("Bearer {}", jwt))
        .send();

    let blob_data = match blob_resp {
        Ok(r) if r.status().is_success() => r.bytes().unwrap_or_default().to_vec(),
        _ => return None,
    };

    if blob_data.len() < 25 {
        return None;
    }

    let blob_nonce = &blob_data[..24];
    let blob_ciphertext = &blob_data[24..];

    let decrypted = decrypt_item(item_key, blob_ciphertext, blob_nonce).ok()?;
    let blob: SecretBlob = serde_json::from_slice(&decrypted).ok()?;
    if blob.item_type == "secret" {
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
        } => fetch_secrets_full(client, api_url, jwt, master_key),
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

    let enc_key = derive_subkey(master_key, b"encrypt").unwrap_or_else(|e| {
        eprintln!("error deriving encryption key: {}", e);
        std::process::exit(1);
    });

    let mut secrets = Vec::new();
    for item in &items {
        let item_id = item["id"].as_str().unwrap_or("").to_string();
        let wrapped_key = json_to_bytes(&item["wrapped_key"]);
        let nonce = json_to_bytes(&item["nonce"]);
        if wrapped_key.is_empty() || nonce.is_empty() {
            continue;
        }

        let item_key_plain = match decrypt_item(&enc_key, &wrapped_key, &nonce) {
            Ok(k) => k,
            Err(_) => continue,
        };
        if item_key_plain.len() != 32 {
            continue;
        }
        let mut item_key = [0u8; 32];
        item_key.copy_from_slice(&item_key_plain);

        if let Some(blob) = decrypt_item_blob(client, api_url, jwt, &item_id, &item_key) {
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

        if let Some(blob) = decrypt_item_blob(client, api_url, jwt, &item_id, &item_key) {
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
        label: label.to_string(),
        item_type: "secret".to_string(),
        value: secret_value,
    };
    let blob_json = serde_json::to_vec(&blob).expect("serialize blob");

    // Generate random item key
    let mut item_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut item_key);

    // Encrypt blob with item key
    let enc_blob = encrypt_item(&item_key, &blob_json).unwrap_or_else(|e| {
        eprintln!("error encrypting: {}", e);
        std::process::exit(1);
    });

    // Build blob: nonce(24) || ciphertext
    let mut blob_data = Vec::with_capacity(24 + enc_blob.ciphertext.len());
    blob_data.extend_from_slice(&enc_blob.nonce);
    blob_data.extend_from_slice(&enc_blob.ciphertext);
    let blob_b64 = STANDARD.encode(&blob_data);

    // Wrap item key with encryption subkey
    let master_key = match &auth {
        AuthContext::Full { master_key, .. } => master_key,
        AuthContext::Scoped { .. } => {
            eprintln!("error: scoped API keys cannot create items");
            std::process::exit(1);
        }
    };
    let enc_key = derive_subkey(master_key, b"encrypt").unwrap_or_else(|e| {
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

    let found = secrets.iter().find(|(_, blob, _)| blob.label == label);
    match found {
        Some((_, blob, _)) => {
            if let Some(path) = output {
                std::fs::write(&path, &blob.value).unwrap_or_else(|e| {
                    eprintln!("error writing {}: {}", path.display(), e);
                    std::process::exit(1);
                });
                eprintln!("Written to {}", path.display());
            } else {
                print!("{}", blob.value);
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
            Some(p) => blob.label.starts_with(p),
            None => true,
        })
        .collect();

    if filtered.is_empty() {
        eprintln!("No secrets found.");
        return;
    }

    for (_, blob, _) in &filtered {
        println!("{}", blob.label);
    }
}

fn run_rm(client: &reqwest::blocking::Client, api_url: &str, label: &str) {
    let auth = get_auth(client, api_url);
    let secrets = fetch_and_decrypt_secrets(client, &auth);

    let found = secrets.iter().find(|(_, blob, _)| blob.label == label);
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

        let value = if raw_value.starts_with('"') {
            // Double-quoted: handle escapes, may span multiple lines
            let mut buf = raw_value[1..].to_string();
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
        } else if raw_value.starts_with('\'') {
            // Single-quoted: literal, no escapes
            let inner = raw_value[1..].strip_suffix('\'').unwrap_or(&raw_value[1..]);
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
    secrets
        .iter()
        .find(|(_, blob, _)| blob.label == label && blob.item_type == "envfile")
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
        label: label.to_string(),
        item_type: "envfile".to_string(),
        value: content,
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
    let enc_key = derive_subkey(master_key, b"encrypt").unwrap_or_else(|e| {
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
                std::fs::write(&path, &blob.value).unwrap_or_else(|e| {
                    eprintln!("error writing {}: {}", path.display(), e);
                    std::process::exit(1);
                });
                eprintln!("Written to {}", path.display());
            } else {
                print!("{}", blob.value);
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

    let env_vars = parse_dotenv(&blob.value);

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

    let env_vars = parse_dotenv(&blob.value);

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
        .filter(|(_, blob, _)| blob.label.starts_with(prefix))
        .collect();

    let mut env_vars: Vec<(String, String)> = Vec::new();
    for (_, blob, _) in &matching {
        let name = blob.label[prefix.len()..]
            .to_uppercase()
            .replace('/', "_")
            .replace('-', "_");
        if name.is_empty() {
            continue;
        }
        env_vars.push((name, blob.value.clone()));
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

        if vault_core::crypto::verify_notarization_signature(&pk, &ch, timestamp_millis, &tr, &sig)
        {
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
