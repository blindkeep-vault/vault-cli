use super::*;

pub fn run_drop_download(
    client: &reqwest::blocking::Client,
    api_url: &str,
    key: &str,
    key2: Option<&str>,
    output: Option<PathBuf>,
) {
    let parsed = parse_input(key, key2);

    match parsed {
        crate::ParsedInput::Direct { drop_id, key } => {
            download_drop(client, api_url, &drop_id, &key, output);
        }
        crate::ParsedInput::Mnemonic { mnemonic, drop_id } => {
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
            let drop_key = unwrap_drop_key(&wrapping_key, &wrapped_bytes).unwrap_or_else(|e| {
                eprintln!("error: failed to unwrap drop key (wrong mnemonic?): {}", e);
                std::process::exit(1);
            });

            download_drop(client, api_url, &resolved_id, &drop_key, output);
        }
    }
}

pub fn parse_input(key: &str, key2: Option<&str>) -> crate::ParsedInput {
    let input = key.trim();

    if let Some(k2) = key2 {
        let k2 = k2.trim();
        if looks_like_uuid(input) {
            if let Some(key_bytes) = try_decode_base64url(k2) {
                return crate::ParsedInput::Direct {
                    drop_id: input.to_string(),
                    key: key_bytes,
                };
            }
        }
        if looks_like_uuid(k2) {
            if let Some(key_bytes) = try_decode_base64url(input) {
                return crate::ParsedInput::Direct {
                    drop_id: k2.to_string(),
                    key: key_bytes,
                };
            }
        }
        let combined = format!("{} {}", input, k2);
        return parse_input(&combined, None);
    }

    if let Some(caps) = extract_drop_url(input) {
        return crate::ParsedInput::Direct {
            drop_id: caps.0,
            key: caps.1,
        };
    }

    if let Some(slug) = extract_pickup_slug(input) {
        let mnemonic = slug.replace('-', " ");
        return crate::ParsedInput::Mnemonic {
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
        return crate::ParsedInput::Mnemonic {
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
        return crate::ParsedInput::Mnemonic {
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

pub fn looks_like_uuid(s: &str) -> bool {
    uuid::Uuid::parse_str(s).is_ok()
}

pub fn try_decode_base64url(s: &str) -> Option<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD.decode(s).ok()?;
    if bytes.len() == 32 {
        Some(bytes.try_into().unwrap())
    } else {
        None
    }
}

pub fn extract_drop_url(s: &str) -> Option<(String, [u8; 32])> {
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

pub fn extract_pickup_slug(s: &str) -> Option<String> {
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

pub fn extract_pickup_uuid(s: &str) -> Option<String> {
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

pub fn download_drop(
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

pub fn run_claim(client: &reqwest::blocking::Client, api_url: &str, key: &str, key2: Option<&str>) {
    let parsed = parse_input(key, key2);

    // Resolve the drop key (32 bytes) and drop ID
    let (drop_id, drop_key) = match parsed {
        crate::ParsedInput::Direct { drop_id, key } => (drop_id, key),
        crate::ParsedInput::Mnemonic { mnemonic, drop_id } => {
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
    let resp = client
        .post(format!("{}/drops/{}/claim", auth.api_url(), drop_id))
        .header("Authorization", format!("Bearer {}", auth.jwt()))
        .json(&serde_json::json!({
            "wrapped_key": wrapped.wrapped_key,
            "nonce": wrapped.nonce.to_vec(),
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
    let item_id = body["id"].as_str().unwrap_or("?");
    eprintln!("Drop claimed! New item ID: {}", item_id);
}

pub fn run_drop_upload(
    client: &reqwest::blocking::Client,
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
    let wrapped_drop_key = wrap_drop_key(&wrapping_key, &drop_key).unwrap_or_else(|e| {
        eprintln!("error: failed to wrap drop key: {}", e);
        std::process::exit(1);
    });

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
