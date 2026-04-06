use super::*;

pub fn run_file_put(
    client: &reqwest::blocking::Client,
    api_url: &str,
    label: &str,
    file_path: &std::path::Path,
) {
    let auth = get_auth(client, api_url);

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

    let master_key = match &auth {
        AuthContext::Full { master_key, .. } => master_key,
        AuthContext::Scoped { .. } => {
            eprintln!("error: scoped API keys cannot create items");
            std::process::exit(1);
        }
    };

    let user_id = load_session().map(|s| s.user_id).unwrap_or_default();
    let blob_aad = format!("item:{}", user_id);
    let wrap_aad_str = format!("wrap:{}", user_id);
    let enc_key = derive_subkey(master_key, b"vault-enc").unwrap_or_else(|e| {
        eprintln!("error: {}", e);
        std::process::exit(1);
    });

    // Encrypt file data with its own key (pad to hide size, same AAD as web UI: "item:{user_id}")
    eprintln!("Encrypting {}...", file_name);
    let mut file_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut file_key);

    let padded = pad_plaintext(&file_data);
    let enc_file = vault_core::crypto::encrypt_item_v1(&file_key, &padded, blob_aad.as_bytes())
        .unwrap_or_else(|e| {
            eprintln!("error encrypting file: {}", e);
            std::process::exit(1);
        });
    let mut file_blob = Vec::with_capacity(1 + 24 + enc_file.ciphertext.len());
    file_blob.push(0x01);
    file_blob.extend_from_slice(&enc_file.nonce);
    file_blob.extend_from_slice(&enc_file.ciphertext);

    // Wrap file key with enc_subkey (stored inside envelope)
    let file_wrapped =
        vault_core::crypto::encrypt_item_v1(&enc_key, &file_key, wrap_aad_str.as_bytes())
            .unwrap_or_else(|e| {
                eprintln!("error: {}", e);
                std::process::exit(1);
            });

    // Build metadata envelope (matches web UI format)
    let blob = SecretBlob {
        name: label.to_string(),
        content: None,
        label: None,
        item_type: Some("document".into()),
        value: None,
        filename: Some(file_name.clone()),
        mime_type: Some(mime_type),
        file_size: Some(file_data.len() as u64),
        file_wrapped_key: Some(file_wrapped.ciphertext.to_vec()),
        file_nonce: Some(file_wrapped.nonce.to_vec()),
    };
    let blob_json = serde_json::to_vec(&blob).expect("serialize blob");

    // Encrypt envelope with its own key
    let mut envelope_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut envelope_key);

    let padded_envelope = pad_plaintext(&blob_json);
    let enc_blob =
        vault_core::crypto::encrypt_item_v1(&envelope_key, &padded_envelope, blob_aad.as_bytes())
            .unwrap_or_else(|e| {
                eprintln!("error encrypting envelope: {}", e);
                std::process::exit(1);
            });
    let mut blob_data = Vec::with_capacity(1 + 24 + enc_blob.ciphertext.len());
    blob_data.push(0x01);
    blob_data.extend_from_slice(&enc_blob.nonce);
    blob_data.extend_from_slice(&enc_blob.ciphertext);
    let envelope_b64 = STANDARD.encode(&blob_data);
    let file_blob_len = file_blob.len();

    // Get presigned upload URL
    eprintln!("Uploading ({} bytes)...", file_blob_len);
    let url_resp: serde_json::Value = client
        .post(format!("{}/items/upload-url", auth.api_url()))
        .header("Authorization", format!("Bearer {}", auth.jwt()))
        .json(&serde_json::json!({ "size_bytes": file_blob_len }))
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

    // Upload file blob to S3 (with API proxy fallback)
    let proxy_upload = url_resp["proxy_upload"].as_bool().unwrap_or(false);
    let upload_result = client.put(upload_url).body(file_blob.clone()).send();
    let needs_fallback = match &upload_result {
        Err(_) => true,
        Ok(resp) => !resp.status().is_success() && proxy_upload,
    };

    if needs_fallback && proxy_upload {
        eprintln!("Direct upload failed, falling back to API proxy...");
        let proxy_resp = client
            .put(format!("{}/items/upload/{}", auth.api_url(), s3_key))
            .header("Authorization", format!("Bearer {}", auth.jwt()))
            .body(file_blob)
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

    // Wrap envelope key with encryption subkey
    let wrapped =
        vault_core::crypto::encrypt_item_v1(&enc_key, &envelope_key, wrap_aad_str.as_bytes())
            .unwrap_or_else(|e| {
                eprintln!("error: {}", e);
                std::process::exit(1);
            });

    // Create item with envelope inline + file blob reference
    let resp = client
        .post(format!("{}/items", auth.api_url()))
        .header("Authorization", format!("Bearer {}", auth.jwt()))
        .json(&serde_json::json!({
            "encrypted_blob": envelope_b64,
            "wrapped_key": wrapped.ciphertext,
            "nonce": wrapped.nonce.to_vec(),
            "item_type": "encrypted",
            "file_blob_key": s3_key,
            "size_bytes": file_blob_len,
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

    eprintln!("File '{}' stored as '{}'.", file_name, label);
}

pub fn run_file_get(
    client: &reqwest::blocking::Client,
    api_url: &str,
    label: &str,
    output: Option<PathBuf>,
) {
    let auth = get_auth(client, api_url);

    // Find the file item by listing and decrypting envelopes
    let (jwt, enc_key, user_id) = match &auth {
        AuthContext::Full {
            jwt,
            master_key,
            api_url: _,
        } => {
            let user_id = load_session().map(|s| s.user_id).unwrap_or_default();
            let enc_key = derive_subkey(master_key, b"vault-enc").unwrap_or_else(|e| {
                eprintln!("error: {}", e);
                std::process::exit(1);
            });
            (jwt.clone(), enc_key, user_id)
        }
        AuthContext::Scoped { .. } => {
            eprintln!("error: file get is not supported with scoped API keys");
            std::process::exit(1);
        }
    };

    let resp = client
        .get(format!("{}/items", auth.api_url()))
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

    let wrap_aad = if user_id.is_empty() {
        Vec::new()
    } else {
        format!("wrap:{}", user_id).into_bytes()
    };
    let blob_aad = if user_id.is_empty() {
        Vec::new()
    } else {
        format!("item:{}", user_id).into_bytes()
    };

    // Find matching file item and keep its item_key
    let mut found: Option<(String, SecretBlob, [u8; 32])> = None;
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
            Err(_) => continue,
        };
        if item_key_plain.len() != 32 {
            continue;
        }
        let mut item_key = [0u8; 32];
        item_key.copy_from_slice(&item_key_plain);

        // Decrypt the inline envelope
        let enc_blob_str = item["encrypted_blob"].as_str().unwrap_or("");
        if enc_blob_str.is_empty() {
            continue;
        }
        let blob_data = STANDARD.decode(enc_blob_str).unwrap_or_default();
        if blob_data.len() < 25 {
            continue;
        }

        let decrypted = if blob_data[0] == 0x01 && blob_data.len() > 25 {
            let n = &blob_data[1..25];
            let ct = &blob_data[25..];
            vault_core::crypto::decrypt_item_auto(&item_key, ct, n, &blob_aad)
                .or_else(|_| decrypt_item(&item_key, &blob_data[24..], &blob_data[..24]))
                .ok()
        } else {
            decrypt_item(&item_key, &blob_data[24..], &blob_data[..24]).ok()
        };

        let Some(decrypted) = decrypted else {
            continue;
        };

        // Envelope may be padded (web UI pads it)
        let envelope_bytes = unpad(&decrypted);

        let Ok(blob) = serde_json::from_slice::<SecretBlob>(envelope_bytes) else {
            continue;
        };

        if blob.is_file() && blob.display_name() == label {
            found = Some((item_id, blob, item_key));
            break;
        }
    }

    let (item_id, blob, _envelope_key) = match found {
        Some(f) => f,
        None => {
            eprintln!("error: file '{}' not found", label);
            std::process::exit(1);
        }
    };

    // Unwrap the file key from the envelope (or fall back to the envelope key)
    let file_key = if let (Some(fwk), Some(fn_)) = (&blob.file_wrapped_key, &blob.file_nonce) {
        let fk_plain = vault_core::crypto::decrypt_item_auto(&enc_key, fwk, fn_, &wrap_aad)
            .unwrap_or_else(|e| {
                eprintln!("error unwrapping file key: {}", e);
                std::process::exit(1);
            });
        if fk_plain.len() != 32 {
            eprintln!("error: invalid file key length");
            std::process::exit(1);
        }
        let mut fk = [0u8; 32];
        fk.copy_from_slice(&fk_plain);
        fk
    } else {
        _envelope_key
    };

    // Download the encrypted file blob
    eprintln!("Downloading...");
    let blob_resp = client
        .get(format!("{}/items/{}/blob", auth.api_url(), item_id))
        .header("Authorization", format!("Bearer {}", jwt))
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

    if !blob_resp.status().is_success() {
        let text = blob_resp.text().unwrap_or_default();
        eprintln!("error downloading file: {}", text);
        std::process::exit(1);
    }

    let raw = blob_resp.bytes().unwrap_or_default().to_vec();

    // Try base64 decode (S3 may return base64-encoded data)
    let file_blob_data = STANDARD.decode(&raw).unwrap_or(raw);

    if file_blob_data.len() < 25 {
        eprintln!("error: file blob too small");
        std::process::exit(1);
    }

    // Decrypt file blob (V1 format, AAD = "item:{user_id}" matching web UI)
    let decrypted = if file_blob_data[0] == 0x01 && file_blob_data.len() > 25 {
        let n = &file_blob_data[1..25];
        let ct = &file_blob_data[25..];
        vault_core::crypto::decrypt_item_auto(&file_key, ct, n, &blob_aad)
    } else {
        decrypt_item(&file_key, &file_blob_data[24..], &file_blob_data[..24])
    }
    .unwrap_or_else(|e| {
        eprintln!("error decrypting file: {}", e);
        std::process::exit(1);
    });

    // Unpad to get original file bytes
    let file_bytes = unpad(&decrypted);

    // Determine output path
    let out_path =
        output.unwrap_or_else(|| PathBuf::from(blob.filename.as_deref().unwrap_or(label)));

    std::fs::write(&out_path, file_bytes).unwrap_or_else(|e| {
        eprintln!("error writing {}: {}", out_path.display(), e);
        std::process::exit(1);
    });

    eprintln!("File '{}' saved to {}", label, out_path.display());
}
