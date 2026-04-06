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

pub fn run_change_password(client: &reqwest::blocking::Client, _api_url: &str) {
    let session = load_session().unwrap_or_else(|| {
        eprintln!("error: not logged in. Run `vault-cli login` first.");
        std::process::exit(1);
    });

    let current_password = prompt_password("Current password: ");
    let new_password = prompt_password("New password: ");
    let new_password2 = prompt_password("Confirm new password: ");

    if new_password != new_password2 {
        eprintln!("error: new passwords do not match");
        std::process::exit(1);
    }

    if new_password.len() < 12 {
        eprintln!("error: password must be at least 12 characters");
        std::process::exit(1);
    }

    if current_password == new_password {
        eprintln!("error: new password must be different from current password");
        std::process::exit(1);
    }

    // Derive current keys
    eprintln!("Deriving current keys...");
    let current_password_key = derive_master_key(current_password.as_bytes(), &session.client_salt)
        .unwrap_or_else(|e| {
            eprintln!("error: key derivation failed: {}", e);
            std::process::exit(1);
        });

    let current_auth_key =
        derive_subkey(&current_password_key, b"vault-auth").unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

    // Unwrap master key with current password
    let master_key = unwrap_master_key_from_profile(client, &session, &current_password_key);

    let current_enc_key = derive_subkey(&current_password_key, b"vault-enc").unwrap_or_else(|e| {
        eprintln!("error: {}", e);
        std::process::exit(1);
    });

    // Fetch profile to get encrypted_private_key and public_key
    let me_resp = client
        .get(format!("{}/auth/me", session.api_url))
        .header("Authorization", format!("Bearer {}", session.jwt))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });
    if !me_resp.status().is_success() {
        eprintln!("error: session expired, please login again");
        std::process::exit(1);
    }
    let me: serde_json::Value = me_resp.json().expect("invalid JSON");
    let public_key = json_to_bytes(&me["public_key"]);
    let encrypted_privkey = json_to_bytes(&me["encrypted_private_key"]);

    // Decrypt private key with current enc_key to verify we can
    let private_key =
        decrypt_private_key(&current_enc_key, &encrypted_privkey).unwrap_or_else(|e| {
            eprintln!(
                "error: wrong current password (cannot decrypt private key): {}",
                e
            );
            std::process::exit(1);
        });

    // Generate new client_salt
    let mut new_client_salt = vec![0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut new_client_salt);

    // Derive new keys
    eprintln!("Deriving new keys...");
    let new_password_key = derive_master_key(new_password.as_bytes(), &new_client_salt)
        .unwrap_or_else(|e| {
            eprintln!("error: key derivation failed: {}", e);
            std::process::exit(1);
        });

    let new_auth_key = derive_subkey(&new_password_key, b"vault-auth").unwrap_or_else(|e| {
        eprintln!("error: {}", e);
        std::process::exit(1);
    });

    let new_enc_key = derive_subkey(&new_password_key, b"vault-enc").unwrap_or_else(|e| {
        eprintln!("error: {}", e);
        std::process::exit(1);
    });

    // Re-encrypt private key with new enc_key
    let enc_privkey = encrypt_item(&new_enc_key, private_key.as_ref()).unwrap_or_else(|e| {
        eprintln!("error encrypting private key: {}", e);
        std::process::exit(1);
    });
    let mut new_encrypted_private_key = Vec::with_capacity(24 + enc_privkey.ciphertext.len());
    new_encrypted_private_key.extend_from_slice(&enc_privkey.nonce);
    new_encrypted_private_key.extend_from_slice(&enc_privkey.ciphertext);

    // Re-encrypt master key with new enc_key (V1 format)
    let mk_aad = format!("master:{}", session.user_id);
    let enc_mk =
        vault_core::crypto::encrypt_item_v1(&new_enc_key, master_key.as_bytes(), mk_aad.as_bytes())
            .unwrap_or_else(|e| {
                eprintln!("error encrypting master key: {}", e);
                std::process::exit(1);
            });
    let mut new_encrypted_master_key = Vec::with_capacity(1 + 24 + enc_mk.ciphertext.len());
    new_encrypted_master_key.push(0x01);
    new_encrypted_master_key.extend_from_slice(&enc_mk.nonce);
    new_encrypted_master_key.extend_from_slice(&enc_mk.ciphertext);

    // Send to server
    eprintln!("Updating password...");
    let resp = client
        .post(format!("{}/auth/set-password", session.api_url))
        .header("Authorization", format!("Bearer {}", session.jwt))
        .json(&serde_json::json!({
            "auth_key": hex::encode(*new_auth_key),
            "public_key": public_key,
            "encrypted_private_key": new_encrypted_private_key,
            "client_salt": new_client_salt,
            "current_auth_key": hex::encode(*current_auth_key),
            "encrypted_master_key": new_encrypted_master_key,
        }))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

    if !resp.status().is_success() {
        let text = resp.text().unwrap_or_default();
        eprintln!("error: password change failed: {}", text);
        std::process::exit(1);
    }

    let auth_resp: serde_json::Value = resp.json().unwrap_or_default();
    let new_jwt = auth_resp["token"]
        .as_str()
        .unwrap_or(&session.jwt)
        .to_string();

    // Update session with new salt and JWT
    save_session(&Session {
        api_url: session.api_url.clone(),
        jwt: new_jwt,
        email: session.email.clone(),
        user_id: session.user_id.clone(),
        client_salt: new_client_salt,
    });

    // Clear agent cache (force re-auth with new password)
    crate::agent::run_lock();

    eprintln!("Password changed successfully.");
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
