use super::*;

pub fn run_will(client: &reqwest::blocking::Client, api_url: &str, action: crate::WillAction) {
    match action {
        crate::WillAction::Create {
            heir,
            grace_days,
            items,
        } => run_create(client, api_url, &heir, grace_days, items.as_deref()),
        crate::WillAction::Show => run_show(api_url),
        crate::WillAction::Update {
            heir,
            grace_days,
            items,
        } => run_update(
            client,
            api_url,
            heir.as_deref(),
            grace_days,
            items.as_deref(),
        ),
        crate::WillAction::Delete => run_delete(api_url),
    }
}

fn build_will_payload(
    client: &reqwest::blocking::Client,
    api_url: &str,
    jwt: &str,
    master_key: &MasterKey,
    heir_email: &str,
    grace_days: u32,
    items_filter: Option<&str>,
) -> serde_json::Value {
    let user_id = load_session().map(|s| s.user_id).unwrap_or_default();
    let vc = VaultClient::new(api_url, jwt);

    // Fetch all items
    let all_items: Vec<serde_json::Value> = vc.get("/items").json().expect("invalid JSON");

    // Filter items if specified
    let filter_labels: Option<Vec<&str>> = items_filter.map(|f| f.split(',').collect());

    // Decrypt item names to match against filter
    let mut selected_items: Vec<(String, [u8; 32])> = Vec::new();
    for item in &all_items {
        let item_id = item["id"].as_str().unwrap_or("").to_string();
        let wrapped_key = json_to_bytes(&item["wrapped_key"]);
        let nonce = json_to_bytes(&item["nonce"]);
        if wrapped_key.is_empty() || nonce.is_empty() {
            continue;
        }

        let item_key = match vault_core::client::unwrap_owned_item_key(
            master_key,
            &user_id,
            &wrapped_key,
            &nonce,
        ) {
            Ok(k) => k,
            Err(_) => continue,
        };

        if let Some(ref labels) = filter_labels {
            // Decrypt blob to get name, check if it matches filter
            let has_file_blob = item["file_blob_key"]
                .as_str()
                .is_some_and(|s| !s.is_empty());
            let blob_opt = if has_file_blob {
                decrypt_inline_envelope(
                    item["encrypted_blob"].as_str().unwrap_or(""),
                    &item_key,
                    &user_id,
                )
            } else {
                decrypt_item_blob(client, api_url, jwt, &item_id, &item_key, &user_id)
            };
            if let Some(blob) = blob_opt {
                if labels.iter().any(|l| *l == blob.display_name()) {
                    selected_items.push((item_id, item_key));
                }
            }
        } else {
            // No filter — include all items
            selected_items.push((item_id, item_key));
        }
    }

    if selected_items.is_empty() {
        eprintln!("error: no items found to include in will");
        std::process::exit(1);
    }
    eprintln!("Including {} item(s) in will.", selected_items.len());

    // Generate will key
    let mut will_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut will_key);

    // Wrap each item key with will_key
    let mut wrapped_items = serde_json::Map::new();
    for (item_id, item_key) in &selected_items {
        let will_aad = format!("will:{}", user_id);
        let wrapped = vault_core::crypto::encrypt_item_v1(&will_key, item_key, will_aad.as_bytes())
            .unwrap_or_else(|e| {
                eprintln!("error wrapping item key for will: {}", e);
                std::process::exit(1);
            });
        wrapped_items.insert(
            item_id.clone(),
            serde_json::json!({
                "wrapped_key": wrapped.ciphertext,
                "nonce": wrapped.nonce.to_vec(),
            }),
        );
    }

    // Try to fetch heir's public key (may 404 if heir has no account)
    let pk_resp = vc.get_query_raw("/users/public-key", &[("email", heir_email)]);
    let heir_has_account = pk_resp.status().is_success();

    if heir_has_account {
        let pk_body: serde_json::Value = pk_resp.json().expect("invalid JSON");
        let heir_pubkey = json_to_array32(&pk_body["public_key"]).unwrap_or_else(|| {
            eprintln!("error: heir has invalid public key");
            std::process::exit(1);
        });

        // Wrap will_key for heir using X25519
        let will_grant =
            vault_core::client::prepare_grant(&will_key, &heir_pubkey).unwrap_or_else(|e| {
                eprintln!("error wrapping will key: {}", e);
                std::process::exit(1);
            });
        let encrypted_will_key = will_grant.grant_wrapped_key;
        let ephemeral_pubkey = will_grant.ephemeral_pubkey;

        serde_json::json!({
            "heir_email": heir_email,
            "encrypted_will_key": encrypted_will_key,
            "ephemeral_pubkey": ephemeral_pubkey.to_vec(),
            "wrapped_items": wrapped_items,
            "grace_days": grace_days,
            "will_key_version": 2,
        })
    } else {
        // Heir not on platform — use link-secret / passphrase flow
        eprintln!("Heir does not have a BlindKeep account. Generating passphrase...");

        let mnemonic = generate_bip39_mnemonic();
        let wrapping_key = derive_drop_wrapping_key(&mnemonic, 2);
        let lookup_key = derive_drop_lookup_key(&mnemonic);

        // Encrypt will_key with wrapping_key
        let enc = encrypt_item(&wrapping_key, &will_key).unwrap_or_else(|e| {
            eprintln!("error encrypting will key: {}", e);
            std::process::exit(1);
        });
        let mut encrypted_will_key = Vec::with_capacity(24 + enc.ciphertext.len());
        encrypted_will_key.extend_from_slice(&enc.nonce);
        encrypted_will_key.extend_from_slice(&enc.ciphertext);

        eprintln!();
        eprintln!("IMPORTANT: Share this passphrase with your heir securely:");
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        for (i, word) in words.iter().enumerate() {
            eprint!("  {:>2}. {:<12}", i + 1, word);
            if (i + 1) % 4 == 0 {
                eprintln!();
            }
        }
        eprintln!();
        eprintln!("Your heir will need this passphrase to access the will.");
        eprintln!("Store it separately from this system.");

        serde_json::json!({
            "heir_email": heir_email,
            "encrypted_will_key": encrypted_will_key,
            "ephemeral_pubkey": [],
            "wrapped_items": wrapped_items,
            "grace_days": grace_days,
            "lookup_key": lookup_key,
            "will_key_version": 2,
        })
    }
}

fn run_create(
    client: &reqwest::blocking::Client,
    api_url: &str,
    heir: &str,
    grace_days: u32,
    items: Option<&str>,
) {
    let auth = get_auth(client, api_url);
    let (jwt, master_key, effective_url) = match &auth {
        AuthContext::Full {
            jwt,
            master_key,
            api_url,
        } => (jwt.as_str(), master_key, api_url.as_str()),
        AuthContext::Scoped { .. } => {
            eprintln!("error: scoped API keys cannot create wills");
            std::process::exit(1);
        }
    };

    let payload = build_will_payload(
        client,
        effective_url,
        jwt,
        master_key,
        heir,
        grace_days,
        items,
    );

    let vc = VaultClient::new(effective_url, jwt);
    vc.post_json("/will", &payload);

    eprintln!("Will created successfully.");
    eprintln!("Heir: {}", heir);
    eprintln!("Grace period: {} days", grace_days);
}

fn run_show(api_url: &str) {
    let session = load_session().unwrap_or_else(|| {
        eprintln!("error: not logged in");
        std::process::exit(1);
    });

    let vc = VaultClient::new(api_url, &session.jwt);
    let resp = vc.get_raw("/will");

    if !resp.status().is_success() {
        if resp.status().as_u16() == 404 {
            eprintln!("No will configured.");
        } else {
            let text = resp.text().unwrap_or_default();
            eprintln!("error: {}", text);
        }
        return;
    }

    let will: serde_json::Value = resp.json().expect("invalid JSON");
    println!(
        "Heir:         {}",
        will["heir_email"].as_str().unwrap_or("?")
    );
    println!(
        "Grace period: {} days",
        will["grace_days"].as_i64().unwrap_or(0)
    );
    println!(
        "Created:      {}",
        will["created_at"].as_str().unwrap_or("?")
    );
    println!(
        "Updated:      {}",
        will["updated_at"].as_str().unwrap_or("?")
    );

    if let Some(items) = will["wrapped_items"].as_object() {
        println!("Items:        {} included", items.len());
    }

    let eph = json_to_bytes(&will["ephemeral_pubkey"]);
    if eph.is_empty() {
        println!("Key type:     passphrase (link-secret)");
    } else {
        println!("Key type:     X25519 (heir has account)");
    }
}

fn run_update(
    client: &reqwest::blocking::Client,
    api_url: &str,
    heir: Option<&str>,
    grace_days: Option<u32>,
    items: Option<&str>,
) {
    let auth = get_auth(client, api_url);
    let (jwt, master_key, effective_url) = match &auth {
        AuthContext::Full {
            jwt,
            master_key,
            api_url,
        } => (jwt.as_str(), master_key, api_url.as_str()),
        AuthContext::Scoped { .. } => {
            eprintln!("error: scoped API keys cannot update wills");
            std::process::exit(1);
        }
    };

    let vc = VaultClient::new(effective_url, jwt);

    // Fetch existing will to get defaults
    let existing_resp = vc.get_raw("/will");
    if !existing_resp.status().is_success() {
        eprintln!("error: no existing will to update");
        std::process::exit(1);
    }
    let existing: serde_json::Value = existing_resp.json().expect("invalid JSON");
    let heir_email = heir.unwrap_or_else(|| existing["heir_email"].as_str().unwrap_or(""));
    let gd = grace_days.unwrap_or(existing["grace_days"].as_u64().unwrap_or(30) as u32);

    let payload = build_will_payload(
        client,
        effective_url,
        jwt,
        master_key,
        heir_email,
        gd,
        items,
    );

    vc.put_json("/will", &payload);
    eprintln!("Will updated successfully.");
}

fn run_delete(api_url: &str) {
    let session = load_session().unwrap_or_else(|| {
        eprintln!("error: not logged in");
        std::process::exit(1);
    });

    let vc = VaultClient::new(api_url, &session.jwt);
    vc.delete("/will");
    eprintln!("Will deleted.");
}
