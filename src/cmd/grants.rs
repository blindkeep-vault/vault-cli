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
        crate::GrantAction::List { sent, received } => {
            run_grant_list(client, api_url, sent, received)
        }
        crate::GrantAction::Access { id, output } => run_grant_access(client, api_url, &id, output),
        crate::GrantAction::Revoke { id } => run_grant_revoke(client, api_url, &id),
        crate::GrantAction::Resend { id } => run_grant_resend(client, api_url, &id),
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

pub fn run_grant_list(
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

pub fn run_grant_revoke(client: &reqwest::blocking::Client, api_url: &str, grant_id: &str) {
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

pub fn run_grant_resend(client: &reqwest::blocking::Client, api_url: &str, grant_id: &str) {
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
