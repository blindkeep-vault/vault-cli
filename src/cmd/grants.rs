use super::*;

pub fn run_grant(client: &reqwest::blocking::Client, api_url: &str, action: crate::GrantAction) {
    match action {
        crate::GrantAction::Create {
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
        crate::GrantAction::List { sent, received } => run_grant_list(api_url, sent, received),
        crate::GrantAction::Access { id, output } => run_grant_access(client, api_url, &id, output),
        crate::GrantAction::Revoke { id } => run_grant_revoke(api_url, &id),
        crate::GrantAction::Resend { id } => run_grant_resend(api_url, &id),
        crate::GrantAction::CreateLink {
            label,
            to,
            max_views,
            expires,
            read_only,
        } => run_grant_create_link(
            client,
            api_url,
            &label,
            to.as_deref(),
            max_views,
            expires.as_deref(),
            read_only,
        ),
        crate::GrantAction::AccessLink { url, key, output } => {
            run_grant_access_link(api_url, &url, key.as_deref(), output)
        }
        crate::GrantAction::Reshare {
            id,
            to,
            max_views,
            expires,
        } => run_grant_reshare(client, api_url, &id, &to, max_views, expires.as_deref()),
    }
}

pub fn run_grant_create(
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

    let vc = VaultClient::new(effective_url, jwt);

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
    let item: serde_json::Value = vc
        .get(&format!("/items/{}", item_id))
        .json()
        .expect("invalid JSON");
    let wrapped_key = json_to_bytes(&item["wrapped_key"]);
    let nonce = json_to_bytes(&item["nonce"]);

    let user_id = load_session().map(|s| s.user_id).unwrap_or_default();
    let item_key =
        vault_core::client::unwrap_owned_item_key(master_key, &user_id, &wrapped_key, &nonce)
            .unwrap_or_else(|e| {
                eprintln!("error decrypting item key: {}", e);
                std::process::exit(1);
            });

    // Fetch recipient's public key
    let pk_resp = vc.get_query_raw("/users/public-key", &[("email", to_email)]);
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
    let recipient_pubkey = json_to_array32(&pk_body["public_key"]).unwrap_or_else(|| {
        eprintln!("error: recipient has invalid public key");
        std::process::exit(1);
    });

    // Wrap item key for recipient (V1 key-bound, grant format: nonce || ciphertext)
    let grant =
        vault_core::client::prepare_grant(&item_key, &recipient_pubkey).unwrap_or_else(|e| {
            eprintln!("error wrapping key: {}", e);
            std::process::exit(1);
        });
    let grant_wrapped_key = grant.grant_wrapped_key;
    let ephemeral_pubkey = grant.ephemeral_pubkey;

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
        let duration = parse_duration(exp).unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });
        let expires_at = (chrono::Utc::now() + duration).to_rfc3339();
        policy["expires_at"] = serde_json::json!(expires_at);
    }

    // POST /grants
    let body: serde_json::Value = vc
        .post_json(
            "/grants",
            &serde_json::json!({
                "item_id": item_id,
                "grantee_email": to_email,
                "wrapped_key": grant_wrapped_key,
                "ephemeral_pubkey": ephemeral_pubkey.to_vec(),
                "policy": policy,
            }),
        )
        .json()
        .unwrap_or_default();
    let grant_id = body["id"].as_str().unwrap_or("(unknown)");
    eprintln!("Grant created: {} -> {}", label, to_email);
    eprintln!("Grant ID: {}", grant_id);
}

pub fn run_grant_list(api_url: &str, sent_only: bool, received_only: bool) {
    let session = load_session().unwrap_or_else(|| {
        eprintln!("error: not logged in");
        std::process::exit(1);
    });

    let vc = VaultClient::new(api_url, &session.jwt);
    let grants: Vec<serde_json::Value> = vc.get("/grants").json().expect("invalid JSON");

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

pub fn run_grant_access(
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

    let vc = VaultClient::new(effective_url, jwt);

    // Access the grant
    let resp = vc.post_json_raw(
        &format!("/grants/{}/access", grant_id),
        &serde_json::json!({"operation": "view"}),
    );

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
    let eph_pub = json_to_array32(&body["ephemeral_pubkey"]).unwrap_or_else(|| {
        eprintln!("error: invalid grant data (bad ephemeral pubkey)");
        std::process::exit(1);
    });

    // Decrypt user's private key
    let me: serde_json::Value = vc.get("/auth/me").json().expect("invalid JSON");
    let encrypted_privkey = json_to_bytes(&me["encrypted_private_key"]);

    let private_key =
        vault_core::client::decrypt_private_key_from_master(master_key, &encrypted_privkey)
            .unwrap_or_else(|e| {
                eprintln!("error decrypting private key: {}", e);
                std::process::exit(1);
            });

    let my_pubkey = json_to_array32(&me["public_key"]).unwrap_or_else(|| {
        eprintln!("error: invalid public key on your account");
        std::process::exit(1);
    });

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

    let plaintext = vault_core::envelope::decrypt_blob_bytes(&blob_data, &item_key, grantor_id)
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

pub fn run_grant_revoke(api_url: &str, grant_id: &str) {
    let session = load_session().unwrap_or_else(|| {
        eprintln!("error: not logged in");
        std::process::exit(1);
    });

    let vc = VaultClient::new(api_url, &session.jwt);
    vc.delete(&format!("/grants/{}", grant_id));
    eprintln!("Grant {} revoked.", grant_id);
}

fn encrypt_claim_secret(claim_key: &[u8; 32], link_secret: &[u8; 32]) -> Vec<u8> {
    vault_core::crypto::encrypt_claim_secret(claim_key, link_secret).unwrap_or_else(|e| {
        eprintln!("error encrypting claim secret: {}", e);
        std::process::exit(1);
    })
}

fn decrypt_claim_secret(claim_key: &[u8; 32], claim_ciphertext: &[u8]) -> [u8; 32] {
    vault_core::crypto::decrypt_claim_secret(claim_key, claim_ciphertext).unwrap_or_else(|e| {
        eprintln!("error decrypting claim secret: {}", e);
        std::process::exit(1);
    })
}

/// Parse a grant-accept URL: /#/grant-accept/{id}/{secret} or full URL
fn parse_grant_url(url: &str) -> Option<(String, String)> {
    // Try: .../grant-accept/{id}/{secret}
    if let Some(idx) = url.find("/grant-accept/") {
        let rest = &url[idx + 14..];
        let parts: Vec<&str> = rest.splitn(3, '/').collect();
        if parts.len() >= 2 && !parts[0].is_empty() && !parts[1].is_empty() {
            let secret = parts[1]
                .split(&['?', '#', '&'][..])
                .next()
                .unwrap_or(parts[1]);
            return Some((parts[0].to_string(), secret.to_string()));
        }
    }
    None
}

pub fn run_grant_create_link(
    client: &reqwest::blocking::Client,
    api_url: &str,
    label: &str,
    to_email: Option<&str>,
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

    let vc = VaultClient::new(effective_url, jwt);

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
    let item: serde_json::Value = vc
        .get(&format!("/items/{}", item_id))
        .json()
        .expect("invalid JSON");
    let wrapped_key = json_to_bytes(&item["wrapped_key"]);
    let nonce = json_to_bytes(&item["nonce"]);

    let user_id = load_session().map(|s| s.user_id).unwrap_or_default();
    let item_key =
        vault_core::client::unwrap_owned_item_key(master_key, &user_id, &wrapped_key, &nonce)
            .unwrap_or_else(|e| {
                eprintln!("error decrypting item key: {}", e);
                std::process::exit(1);
            });

    // Generate random link_secret
    let mut link_secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut link_secret);

    // Wrap item_key with link_secret (no AAD initially; AAD added after we know grant_id)
    let ls_wrapped = vault_core::crypto::encrypt_item_v1(&link_secret, &item_key, b"")
        .unwrap_or_else(|e| {
            eprintln!("error wrapping key with link-secret: {}", e);
            std::process::exit(1);
        });

    // Generate claim_key and encrypt link_secret
    let mut claim_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut claim_key);
    let claim_ciphertext = encrypt_claim_secret(&claim_key, &link_secret);

    // Hash claim_key for server-side lookup
    let mut hasher = Sha256::new();
    hasher.update(claim_key);
    let claim_token_hash = hex::encode(hasher.finalize());

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
        let duration = parse_duration(exp).unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });
        let expires_at = (chrono::Utc::now() + duration).to_rfc3339();
        policy["expires_at"] = serde_json::json!(expires_at);
    }

    let grantee_email = to_email.unwrap_or("link-secret@blindkeep.com");

    // POST /grants with empty ephemeral_pubkey (link-secret mode)
    let mut grant_body = serde_json::json!({
        "item_id": item_id,
        "grantee_email": grantee_email,
        "wrapped_key": ls_wrapped.ciphertext,
        "ephemeral_pubkey": [],
        "policy": policy,
        "claim_token_hash": claim_token_hash,
        "claim_ciphertext": claim_ciphertext,
    });

    // Handle file_wrapped_key if item has one
    let has_file_blob = item["file_blob_key"]
        .as_str()
        .is_some_and(|s| !s.is_empty());
    if has_file_blob {
        // Decrypt the file_wrapped_key, then re-wrap with link_secret
        let file_wk = json_to_bytes(&item["file_wrapped_key"]);
        let file_nonce = json_to_bytes(&item["file_nonce"]);
        if !file_wk.is_empty() && !file_nonce.is_empty() {
            let file_key = vault_core::client::unwrap_owned_item_key(
                master_key,
                &user_id,
                &file_wk,
                &file_nonce,
            )
            .unwrap_or_else(|e| {
                eprintln!("error decrypting file key: {}", e);
                std::process::exit(1);
            });
            let file_key_plain = vault_core::Zeroizing::new(file_key.to_vec());
            // Wrap file key with link_secret: nonce(24) + ciphertext
            let file_enc = encrypt_item(&link_secret, &file_key_plain).unwrap_or_else(|e| {
                eprintln!("error wrapping file key: {}", e);
                std::process::exit(1);
            });
            let mut file_wrapped: Vec<u8> = Vec::with_capacity(24 + file_enc.ciphertext.len());
            file_wrapped.extend_from_slice(&file_enc.nonce);
            file_wrapped.extend_from_slice(&file_enc.ciphertext);
            grant_body["file_wrapped_key"] = serde_json::json!(file_wrapped);
        }
    }

    let body: serde_json::Value = vc
        .post_json("/grants", &grant_body)
        .json()
        .unwrap_or_default();
    let grant_id = body["id"].as_str().unwrap_or("?");

    // Build share URL
    let claim_key_b64 = URL_SAFE_NO_PAD.encode(claim_key);
    let base_url = effective_url
        .replace("://api.", "://app.")
        .replace("://localhost:3000", "://localhost:8080");
    let share_url = format!("{}/#/grant-accept/{}/{}", base_url, grant_id, claim_key_b64);

    // Optionally send the link via email
    if to_email.is_some() {
        let _ = vc.post_json_raw(
            &format!("/grants/{}/send-link", grant_id),
            &serde_json::json!({ "share_url": share_url }),
        );
    }

    eprintln!("Link-secret grant created.");
    eprintln!("Grant ID: {}", grant_id);
    eprintln!();
    eprintln!("Share URL:");
    println!("{}", share_url);
}

pub fn run_grant_access_link(
    api_url: &str,
    url: &str,
    key_arg: Option<&str>,
    output: Option<PathBuf>,
) {
    // Parse grant_id and claim_key from URL or args
    let (grant_id, claim_key_b64) = if let Some((id, secret)) = parse_grant_url(url) {
        (id, secret)
    } else if uuid::Uuid::parse_str(url).is_ok() {
        let k = key_arg.unwrap_or_else(|| {
            eprintln!("error: provide a grant URL or grant ID with --key");
            std::process::exit(1);
        });
        (url.to_string(), k.to_string())
    } else {
        eprintln!("error: could not parse grant URL");
        std::process::exit(1);
    };

    let claim_key_bytes = URL_SAFE_NO_PAD.decode(&claim_key_b64).unwrap_or_else(|e| {
        eprintln!("error decoding claim key: {}", e);
        std::process::exit(1);
    });
    if claim_key_bytes.len() != 32 {
        eprintln!("error: claim key has wrong length (expected 32 bytes)");
        std::process::exit(1);
    }
    let mut claim_key = [0u8; 32];
    claim_key.copy_from_slice(&claim_key_bytes);

    // Hash claim_key for server lookup
    let mut hasher = Sha256::new();
    hasher.update(claim_key);
    let token_hash = hex::encode(hasher.finalize());

    let vc = VaultClient::new(api_url, "");

    // Try claim-token endpoint (works unauthenticated or authenticated)
    let preview_resp = vc.post_json_unauth_raw(
        &format!("/grants/{}/preview", grant_id),
        &serde_json::json!({ "token_hash": token_hash }),
    );

    if !preview_resp.status().is_success() {
        let text = preview_resp.text().unwrap_or_default();
        eprintln!("error: failed to access grant: {}", text);
        std::process::exit(1);
    }

    let grant: serde_json::Value = preview_resp.json().expect("invalid JSON");

    // Decrypt claim_ciphertext to get link_secret
    let claim_ct = json_to_bytes(&grant["claim_ciphertext"]);
    let link_secret = decrypt_claim_secret(&claim_key, &claim_ct);

    // Decrypt item key using link_secret
    let grant_wrapped_key = json_to_bytes(&grant["wrapped_key"]);
    if grant_wrapped_key.len() < 25 {
        eprintln!("error: grant wrapped_key too short");
        std::process::exit(1);
    }

    // wrapped_key format: the server stores it as ciphertext only; nonce is separate
    // But for link-secret grants from the web UI, wrapped_key is just the ciphertext
    // and nonce is stored separately
    let grant_nonce = json_to_bytes(&grant["nonce"]);
    let item_key_plain =
        vault_core::crypto::decrypt_item_auto(&link_secret, &grant_wrapped_key, &grant_nonce, b"")
            .unwrap_or_else(|e| {
                eprintln!("error decrypting item key: {}", e);
                std::process::exit(1);
            });
    let mut item_key = [0u8; 32];
    item_key.copy_from_slice(&item_key_plain);

    // Decrypt the blob
    let encrypted_blob_b64 = grant["encrypted_blob"].as_str().unwrap_or("");
    let blob_data = STANDARD.decode(encrypted_blob_b64).unwrap_or_else(|e| {
        eprintln!("error decoding blob: {}", e);
        std::process::exit(1);
    });
    if blob_data.len() < 25 {
        eprintln!("error: encrypted blob too short");
        std::process::exit(1);
    }

    let grantor_id = grant["grantor_id"].as_str().unwrap_or("");

    let plaintext = vault_core::envelope::decrypt_blob_bytes(&blob_data, &item_key, grantor_id)
        .unwrap_or_else(|e| {
            eprintln!("error decrypting grant content: {}", e);
            std::process::exit(1);
        });

    // Output
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
    } else if let Ok(text) = std::str::from_utf8(&plaintext) {
        if let Some(path) = output {
            std::fs::write(&path, text).unwrap_or_else(|e| {
                eprintln!("error writing {}: {}", path.display(), e);
                std::process::exit(1);
            });
            eprintln!("Written to {}", path.display());
        } else {
            print!("{}", text);
        }
    } else if let Some(path) = output {
        std::fs::write(&path, &*plaintext).unwrap_or_else(|e| {
            eprintln!("error writing {}: {}", path.display(), e);
            std::process::exit(1);
        });
        eprintln!("Written to {}", path.display());
    } else {
        eprintln!("error: grant content is binary (use -o to save to file)");
        std::process::exit(1);
    }
}

pub fn run_grant_reshare(
    client: &reqwest::blocking::Client,
    api_url: &str,
    grant_id: &str,
    to_email: &str,
    max_views: Option<u32>,
    expires: Option<&str>,
) {
    let auth = get_auth(client, api_url);
    let (jwt, master_key, effective_url) = match &auth {
        AuthContext::Full {
            jwt,
            master_key,
            api_url,
        } => (jwt.as_str(), master_key, api_url.as_str()),
        AuthContext::Scoped { .. } => {
            eprintln!("error: scoped API keys cannot reshare grants");
            std::process::exit(1);
        }
    };

    let vc = VaultClient::new(effective_url, jwt);

    // Access the grant to get the item key
    let resp = vc.post_json_raw(
        &format!("/grants/{}/access", grant_id),
        &serde_json::json!({"operation": "view"}),
    );

    if !resp.status().is_success() {
        let text = resp.text().unwrap_or_default();
        eprintln!("error accessing grant: {}", text);
        std::process::exit(1);
    }

    let body: serde_json::Value = resp.json().expect("invalid JSON");

    // Decrypt item key from grant
    let grant_wrapped_key = json_to_bytes(&body["wrapped_key"]);
    let eph_pub = json_to_array32(&body["ephemeral_pubkey"]).unwrap_or_else(|| {
        eprintln!("error: invalid key data on grant");
        std::process::exit(1);
    });

    let me: serde_json::Value = vc.get("/auth/me").json().expect("invalid JSON");
    let encrypted_privkey = json_to_bytes(&me["encrypted_private_key"]);

    let private_key =
        vault_core::client::decrypt_private_key_from_master(master_key, &encrypted_privkey)
            .unwrap_or_else(|e| {
                eprintln!("error decrypting private key: {}", e);
                std::process::exit(1);
            });

    let my_pubkey = json_to_array32(&me["public_key"]).unwrap_or_else(|| {
        eprintln!("error: invalid key data on grant");
        std::process::exit(1);
    });

    let item_key = unwrap_grant_key(&private_key, &eph_pub, &grant_wrapped_key, &my_pubkey)
        .unwrap_or_else(|e| {
            eprintln!("error unwrapping grant key: {}", e);
            std::process::exit(1);
        });

    // Fetch recipient's public key
    let pk_resp = vc.get_query_raw("/users/public-key", &[("email", to_email)]);
    if !pk_resp.status().is_success() {
        if pk_resp.status().as_u16() == 404 {
            eprintln!(
                "error: user '{}' not found (must be a verified BlindKeep user)",
                to_email
            );
        } else {
            eprintln!("error: failed to fetch public key for '{}'", to_email);
        }
        std::process::exit(1);
    }
    let pk_body: serde_json::Value = pk_resp.json().expect("invalid JSON");
    let recipient_pubkey = json_to_array32(&pk_body["public_key"]).unwrap_or_else(|| {
        eprintln!("error: recipient has invalid public key");
        std::process::exit(1);
    });

    // Wrap item key for new recipient
    let new_grant =
        vault_core::client::prepare_grant(&item_key, &recipient_pubkey).unwrap_or_else(|e| {
            eprintln!("error wrapping key: {}", e);
            std::process::exit(1);
        });
    let new_wrapped_key = new_grant.grant_wrapped_key;
    let new_eph_pubkey = new_grant.ephemeral_pubkey;

    // Build policy
    let mut policy = serde_json::json!({
        "allowed_ops": ["view", "download"],
        "notify_on_access": false,
    });
    if let Some(n) = max_views {
        policy["max_views"] = serde_json::json!(n);
    }
    if let Some(exp) = expires {
        let duration = parse_duration(exp).unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });
        let expires_at = (chrono::Utc::now() + duration).to_rfc3339();
        policy["expires_at"] = serde_json::json!(expires_at);
    }

    // Get item_id from the original grant
    let item_id = body["item_id"].as_str().unwrap_or("");

    // Create new grant for recipient
    let result: serde_json::Value = vc
        .post_json(
            "/grants",
            &serde_json::json!({
                "item_id": item_id,
                "grantee_email": to_email,
                "wrapped_key": new_wrapped_key,
                "ephemeral_pubkey": new_eph_pubkey.to_vec(),
                "policy": policy,
            }),
        )
        .json()
        .unwrap_or_default();
    let new_grant_id = result["id"].as_str().unwrap_or("?");
    eprintln!(
        "Grant reshared: {} -> {} (new grant ID: {})",
        grant_id, to_email, new_grant_id
    );
}

pub fn run_grant_resend(api_url: &str, grant_id: &str) {
    let session = load_session().unwrap_or_else(|| {
        eprintln!("error: not logged in");
        std::process::exit(1);
    });

    let vc = VaultClient::new(api_url, &session.jwt);
    let resp = vc.post_json_raw(
        &format!("/grants/{}/resend", grant_id),
        &serde_json::json!({}),
    );

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
