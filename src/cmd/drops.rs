use super::*;

pub fn run_drop_download(
    _client: &reqwest::blocking::Client,
    api_url: &str,
    key: &str,
    key2: Option<&str>,
    output: Option<PathBuf>,
) {
    let parsed = parse_input(key, key2);

    match parsed {
        vault_core::parsing::DropInput::Direct { drop_id, key } => {
            download_drop(api_url, &drop_id, &key, output);
        }
        vault_core::parsing::DropInput::Mnemonic { mnemonic, drop_id } => {
            let vc = VaultClient::new(api_url, "");

            let resolved_id = match drop_id {
                Some(id) => id,
                None => {
                    eprintln!("Looking up drop by mnemonic...");
                    let lookup_key = derive_drop_lookup_key(&mnemonic);
                    let resp = vc.get_unauth_raw(&format!("/drops/by-words/{}", lookup_key));
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

            let resp = vc.get_unauth_raw(&format!("/drops/{}", resolved_id));
            if !resp.status().is_success() {
                eprintln!("error: drop not found");
                std::process::exit(1);
            }
            let drop_meta: serde_json::Value = resp.json().expect("invalid JSON");
            if drop_meta["claimed"].as_bool() == Some(true) {
                eprintln!("error: drop already claimed");
                std::process::exit(1);
            }

            let wrapped_bytes = json_to_bytes(&drop_meta["wrapped_drop_key"]);
            if wrapped_bytes.is_empty() {
                eprintln!("error: drop has no wrapped_drop_key (not a mnemonic drop)");
                std::process::exit(1);
            }

            let version = drop_meta["drop_key_version"].as_i64().unwrap_or(1) as i32;
            eprintln!("Deriving wrapping key (v{})...", version);
            let wrapping_key = derive_drop_wrapping_key(&mnemonic, version);
            let drop_key = unwrap_drop_key(&wrapping_key, &wrapped_bytes).unwrap_or_else(|e| {
                eprintln!("error: failed to unwrap drop key (wrong mnemonic?): {}", e);
                std::process::exit(1);
            });

            download_drop(api_url, &resolved_id, &drop_key, output);
        }
    }
}

pub fn parse_input(key: &str, key2: Option<&str>) -> crate::ParsedInput {
    vault_core::parsing::parse_drop_input(key, key2).unwrap_or_else(|e| {
        eprintln!("error: {}", e);
        std::process::exit(1);
    })
}

pub fn download_drop(api_url: &str, drop_id: &str, key: &[u8; 32], output: Option<PathBuf>) {
    eprintln!("Downloading drop {}...", drop_id);
    let vc = VaultClient::new(api_url, "");
    let resp = vc.get_unauth(&format!("/drops/{}/blob", drop_id));
    let encrypted = resp.bytes().expect("failed to read body");
    let encrypted = encrypted.as_ref();

    if encrypted.len() < 24 {
        eprintln!("error: blob too short");
        std::process::exit(1);
    }

    let nonce = &encrypted[..24];
    let ciphertext = &encrypted[24..];

    eprintln!("Decrypting...");
    let padded = vault_core::crypto::decrypt_item_auto(key, ciphertext, nonce, b"drop-blob")
        .unwrap_or_else(|e| {
            eprintln!("error: decryption failed: {}", e);
            std::process::exit(1);
        });

    let plain = unpad(&padded).unwrap_or_else(|e| {
        eprintln!("error: unpad failed: {}", e);
        std::process::exit(1);
    });
    let (filename, file_data) = parse_envelope(plain, drop_id);

    let out_path = output.unwrap_or_else(|| PathBuf::from(&filename));
    std::fs::write(&out_path, file_data).unwrap_or_else(|e| {
        eprintln!("error writing {}: {}", out_path.display(), e);
        std::process::exit(1);
    });
    eprintln!("Saved to {}", out_path.display());
}

pub fn run_claim(client: &reqwest::blocking::Client, api_url: &str, key: &str, key2: Option<&str>) {
    let parsed = parse_input(key, key2);
    let vc = VaultClient::new(api_url, "");

    // Resolve the drop key (32 bytes) and drop ID
    let (drop_id, drop_key) = match parsed {
        vault_core::parsing::DropInput::Direct { drop_id, key } => (drop_id, key),
        vault_core::parsing::DropInput::Mnemonic { mnemonic, drop_id } => {
            let resolved_id = match drop_id {
                Some(id) => id,
                None => {
                    eprintln!("Looking up drop by mnemonic...");
                    let lookup_key = derive_drop_lookup_key(&mnemonic);
                    let resp = vc.get_unauth_raw(&format!("/drops/by-words/{}", lookup_key));
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

            let resp = vc.get_unauth_raw(&format!("/drops/{}", resolved_id));
            if !resp.status().is_success() {
                eprintln!("error: drop not found");
                std::process::exit(1);
            }
            let drop_meta: serde_json::Value = resp.json().expect("invalid JSON");
            if drop_meta["claimed"].as_bool() == Some(true) {
                eprintln!("error: drop already claimed");
                std::process::exit(1);
            }

            let wrapped_bytes = json_to_bytes(&drop_meta["wrapped_drop_key"]);
            if wrapped_bytes.is_empty() {
                eprintln!("error: drop has no wrapped_drop_key (not a mnemonic drop)");
                std::process::exit(1);
            }

            let version = drop_meta["drop_key_version"].as_i64().unwrap_or(1) as i32;
            eprintln!("Deriving wrapping key (v{})...", version);
            let wrapping_key = derive_drop_wrapping_key(&mnemonic, version);
            let dk = unwrap_drop_key(&wrapping_key, &wrapped_bytes).unwrap_or_else(|e| {
                eprintln!("error: failed to unwrap drop key (wrong mnemonic?): {}", e);
                std::process::exit(1);
            });

            let mut dk_arr = [0u8; 32];
            dk_arr.copy_from_slice(dk.as_ref());
            (resolved_id, dk_arr)
        }
    };

    // Authenticate to wrap the key for our vault
    let auth = get_auth(client, api_url);
    let master_key = match &auth {
        AuthContext::Full { master_key, .. } => master_key,
        AuthContext::Scoped { .. } => {
            eprintln!("error: scoped API keys cannot claim drops");
            std::process::exit(1);
        }
    };

    let user_id = load_session().map(|s| s.user_id).unwrap_or_default();

    // Wrap the drop key under our enc_key (V1 with AAD)
    let wrapped = vault_core::client::wrap_key_for_user(master_key, &user_id, &drop_key)
        .unwrap_or_else(|e| {
            eprintln!("error wrapping key: {}", e);
            std::process::exit(1);
        });

    // POST /drops/:id/claim
    let auth_vc = VaultClient::from_auth(&auth);
    let body: serde_json::Value = auth_vc
        .post_json(
            &format!("/drops/{}/claim", drop_id),
            &serde_json::json!({
                "wrapped_key": wrapped.wrapped_key,
                "nonce": wrapped.nonce.to_vec(),
            }),
        )
        .json()
        .unwrap_or_default();
    let item_id = body["id"].as_str().unwrap_or("?");
    eprintln!("Drop claimed! New item ID: {}", item_id);
}

pub fn run_drop_upload(
    _client: &reqwest::blocking::Client,
    api_url: &str,
    file_path: &std::path::Path,
) {
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

    let enc = vault_core::crypto::encrypt_item_v1(&drop_key, &padded, b"drop-blob")
        .expect("encryption failed");

    // Build blob: nonce(24) + V1 ciphertext
    let mut blob = Vec::with_capacity(24 + enc.ciphertext.len());
    blob.extend_from_slice(&enc.nonce);
    blob.extend_from_slice(&enc.ciphertext);

    // Generate BIP39 mnemonic and derive keys
    let mnemonic = generate_bip39_mnemonic();
    let lookup_key = derive_drop_lookup_key(&mnemonic);

    eprintln!("Deriving wrapping key...");
    let wrapping_key = derive_drop_wrapping_key(&mnemonic, 2);
    let wrapped_drop_key = wrap_drop_key(&wrapping_key, &drop_key).unwrap_or_else(|e| {
        eprintln!("error: failed to wrap drop key: {}", e);
        std::process::exit(1);
    });

    let vc = VaultClient::new(api_url, "");

    // Get presigned upload URL
    eprintln!("Uploading ({} bytes)...", blob.len());
    let url_resp: serde_json::Value = vc
        .post_json_unauth(
            "/drops/upload-url",
            &serde_json::json!({ "size_bytes": blob.len() }),
        )
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
    let upload_result = vc.inner().put(upload_url).body(blob.clone()).send();
    let needs_fallback = match &upload_result {
        Err(_) => true,
        Ok(resp) => !resp.status().is_success() && proxy_upload,
    };

    if needs_fallback && proxy_upload {
        eprintln!("Direct upload failed, falling back to API proxy...");
        let proxy_resp = vc
            .inner()
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

    let drop_resp: serde_json::Value = vc
        .post_json_unauth(
            "/drops",
            &serde_json::json!({
                "s3_key": s3_key,
                "size_bytes": blob.len(),
                "nonce": nonce_array,
                "wrapped_drop_key": wrapped_array,
                "lookup_key": lookup_key,
                "drop_key_version": 2,
            }),
        )
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
