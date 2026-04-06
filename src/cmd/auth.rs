use super::*;

pub fn run_register(client: &reqwest::blocking::Client, api_url: &str) {
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

pub fn run_login(client: &reqwest::blocking::Client, api_url: &str) {
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
    crate::agent::run_start_quiet(30);
    let master_key = unwrap_master_key_from_profile(client, &session, &password_key);
    crate::agent::try_store(
        &session.jwt,
        &master_key,
        &session.api_url,
        &session.user_id,
    );

    eprintln!("Logged in as {}", email);
}

pub fn run_logout() {
    clear_session();
    eprintln!("Logged out.");
}

pub fn run_status(api_url: &str) {
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
    crate::agent::run_status();
}
