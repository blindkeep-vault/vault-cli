use super::*;

// --- API Key management ---

pub fn run_apikey(client: &reqwest::blocking::Client, api_url: &str, action: crate::ApikeyAction) {
    match action {
        crate::ApikeyAction::Create {
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
        crate::ApikeyAction::List => run_apikey_list(client, api_url),
        crate::ApikeyAction::Revoke { id } => run_apikey_revoke(client, api_url, &id),
        crate::ApikeyAction::Grant { key_id, label } => {
            run_apikey_grant(client, api_url, &key_id, &label)
        }
        crate::ApikeyAction::Grants { key_id } => run_apikey_grants(client, api_url, &key_id),
        crate::ApikeyAction::Ungrant { key_id, label } => {
            run_apikey_ungrant(client, api_url, &key_id, &label)
        }
        crate::ApikeyAction::Rotate { key } => run_apikey_rotate(client, api_url, &key),
    }
}

pub fn run_apikey_create(
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

    #[allow(clippy::type_complexity)]
    let (secret, key_prefix, auth_key_hex, wrapped_master_key, encrypted_private_key, public_key): (
        [u8; 32],
        String,
        String,
        Option<Vec<u8>>,
        Vec<u8>,
        Option<Vec<u8>>,
    ) = if scoped {
        eprintln!("Generating scoped API key...");
        let prepared = vault_core::client::prepare_api_key_scoped().unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });
        (
            prepared.secret,
            prepared.key_prefix,
            prepared.auth_key_hex,
            None,
            prepared.encrypted_private_key,
            Some(prepared.public_key.to_vec()),
        )
    } else {
        // Full-access key: wrap user's master key
        let password = prompt_password("Password (to wrap master key): ");
        eprintln!("Deriving master key...");
        let login = vault_core::client::prepare_login(&password, &session.client_salt)
            .unwrap_or_else(|e| {
                eprintln!("error: key derivation failed: {}", e);
                std::process::exit(1);
            });
        let master_key = unwrap_master_key_from_profile(client, &session, &login.master_key);

        eprintln!("Wrapping master key...");
        let prepared = vault_core::client::prepare_api_key_full(&master_key).unwrap_or_else(|e| {
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

        (
            prepared.secret,
            prepared.key_prefix,
            prepared.auth_key_hex,
            Some(prepared.wrapped_master_key),
            epk,
            None,
        )
    };

    let expires_at = expires.map(|e| {
        let now = chrono::Utc::now();
        let duration = parse_duration(e);
        (now + duration).to_rfc3339()
    });

    let mut body = serde_json::json!({
        "name": name,
        "auth_key": auth_key_hex,
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

pub fn run_apikey_list(client: &reqwest::blocking::Client, api_url: &str) {
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

pub fn run_apikey_revoke(client: &reqwest::blocking::Client, api_url: &str, id: &str) {
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

pub fn run_apikey_grant(
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
    let login =
        vault_core::client::prepare_login(&password, &session.client_salt).unwrap_or_else(|e| {
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
        master_key: login.master_key,
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

    // Fetch the item to get wrapped_key and nonce, then unwrap + re-wrap for API key
    let mk = match &auth {
        AuthContext::Full { master_key, .. } => master_key,
        _ => unreachable!(),
    };
    let user_id = load_session().map(|s| s.user_id).unwrap_or_default();
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

    let grant_wrap =
        vault_core::client::grant_item_to_api_key(mk, &user_id, &wrapped_key, &nonce, &api_pubkey)
            .unwrap_or_else(|e| {
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

pub fn run_apikey_grants(client: &reqwest::blocking::Client, api_url: &str, key_id: &str) {
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

pub fn run_apikey_ungrant(
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
    let login =
        vault_core::client::prepare_login(&password, &session.client_salt).unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

    let auth = AuthContext::Full {
        jwt: session.jwt.clone(),
        master_key: login.master_key,
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

pub fn run_apikey_rotate(client: &reqwest::blocking::Client, api_url: &str, key_ref: &str) {
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
        let login = vault_core::client::prepare_login(&password, &session.client_salt)
            .unwrap_or_else(|e| {
                eprintln!("error: {}", e);
                std::process::exit(1);
            });

        let wmk = wrap_master_key(&wrapping_key, &login.master_key).unwrap_or_else(|e| {
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
        let login = vault_core::client::prepare_login(&password, &session.client_salt)
            .unwrap_or_else(|e| {
                eprintln!("error: {}", e);
                std::process::exit(1);
            });
        let user_id = load_session().map(|s| s.user_id).unwrap_or_default();

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

                // Unwrap item key and wrap for new API key's public key
                let grant_wrap = match vault_core::client::grant_item_to_api_key(
                    &login.master_key,
                    &user_id,
                    &wrapped_key,
                    &nonce,
                    &new_pubkey,
                ) {
                    Ok(g) => g,
                    Err(e) => {
                        eprintln!("warning: could not re-wrap item key for {}: {}", item_id, e);
                        continue;
                    }
                };

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
