use super::*;

// --- Session management ---

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Session {
    pub api_url: String,
    pub jwt: String,
    pub email: String,
    pub user_id: String,
    pub client_salt: Vec<u8>,
}

pub fn session_dir() -> PathBuf {
    dirs::home_dir()
        .expect("cannot determine home directory")
        .join(".vault")
}

pub fn session_path() -> PathBuf {
    session_dir().join("session.json")
}

pub fn load_session() -> Option<Session> {
    let data = std::fs::read_to_string(session_path()).ok()?;
    serde_json::from_str(&data).ok()
}

pub fn save_session(session: &Session) {
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

pub fn clear_session() {
    let _ = std::fs::remove_file(session_path());
}

/// Authentication context for commands that need crypto access.
pub enum AuthContext {
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
    pub fn jwt(&self) -> &str {
        match self {
            AuthContext::Full { jwt, .. } => jwt,
            AuthContext::Scoped { jwt, .. } => jwt,
        }
    }

    pub fn api_url(&self) -> &str {
        match self {
            AuthContext::Full { api_url, .. } => api_url,
            AuthContext::Scoped { api_url, .. } => api_url,
        }
    }
}

pub fn prompt_password(prompt: &str) -> String {
    rpassword::prompt_password(prompt).unwrap_or_else(|e| {
        eprintln!("error reading password: {}", e);
        std::process::exit(1);
    })
}

pub fn prompt_line(prompt: &str) -> String {
    eprint!("{}", prompt);
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap_or_else(|e| {
        eprintln!("error reading input: {}", e);
        std::process::exit(1);
    });
    line.trim().to_string()
}

pub fn get_auth(client: &reqwest::blocking::Client, api_url: &str) -> AuthContext {
    // Priority 1: VAULT_API_KEY env var
    if let Ok(api_key) = std::env::var("VAULT_API_KEY") {
        return auth_with_api_key(client, api_url, &api_key);
    }
    // Priority 2: Running agent with cached key
    if let Some((jwt, master_key, _cached_url, _user_id)) = crate::agent::try_retrieve() {
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

        // Start agent (if not already running) and cache credentials
        crate::agent::run_start_quiet(30);
        crate::agent::try_store(
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

pub fn unwrap_master_key_from_profile(
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

    vault_core::unlock::unwrap_master_key_from_encrypted(
        &encrypted_master_key,
        password_key,
        &session.user_id,
    )
    .unwrap_or_else(|e| {
        eprintln!("error unwrapping master key: {}", e);
        std::process::exit(1);
    })
}

pub fn parse_api_key(raw_key: &str) -> (String, vault_core::Zeroizing<[u8; 32]>) {
    vault_core::unlock::parse_api_key(raw_key).unwrap_or_else(|e| {
        eprintln!("error: {}", e);
        std::process::exit(1);
    })
}

pub fn json_to_bytes(val: &serde_json::Value) -> Vec<u8> {
    match val.as_array() {
        Some(a) => a.iter().map(|v| v.as_u64().unwrap_or(0) as u8).collect(),
        None => Vec::new(),
    }
}

pub fn auth_with_api_key(
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

pub fn parse_duration(s: &str) -> chrono::Duration {
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

// --- Secret CRUD ---

pub fn decrypt_item_blob(
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
    let decrypted = vault_core::envelope::decrypt_blob_bytes(&blob_data, item_key, user_id).ok()?;
    let blob: SecretBlob = serde_json::from_slice(&decrypted).ok()?;
    if blob.is_secret() || blob.is_file() {
        Some(blob)
    } else {
        None
    }
}

pub fn fetch_and_decrypt_secrets(
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

pub fn fetch_secrets_full(
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
    let mut skipped_decrypt = 0usize;
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
            Err(_) => {
                skipped_decrypt += 1;
                continue;
            }
        };
        if item_key_plain.len() != 32 {
            skipped_decrypt += 1;
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

    if skipped_decrypt > 0 {
        eprintln!(
            "warning: {} item(s) could not be decrypted (key mismatch or corruption)",
            skipped_decrypt
        );
    }

    secrets
}

pub fn fetch_secrets_scoped(
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
