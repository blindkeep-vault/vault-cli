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

    eprintln!("Encrypting {}...", file_name);
    let prepared = vault_core::client::prepare_file_item(
        master_key, &user_id, label, &file_name, &mime_type, &file_data,
    )
    .unwrap_or_else(|e| {
        eprintln!("error encrypting file: {}", e);
        std::process::exit(1);
    });

    let file_blob = prepared.encrypted_file;
    let envelope_b64 = prepared.envelope_b64.clone();
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

    // Create item with envelope inline + file blob reference
    let resp = client
        .post(format!("{}/items", auth.api_url()))
        .header("Authorization", format!("Bearer {}", auth.jwt()))
        .json(&serde_json::json!({
            "encrypted_blob": envelope_b64,
            "wrapped_key": prepared.wrapped_key,
            "nonce": prepared.nonce.to_vec(),
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
    let (jwt, master_key, user_id) = match &auth {
        AuthContext::Full {
            jwt, master_key, ..
        } => {
            let user_id = load_session().map(|s| s.user_id).unwrap_or_default();
            (jwt.clone(), master_key, user_id)
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

    // Find matching file item and keep its item_key
    let mut found: Option<(String, SecretBlob, [u8; 32])> = None;
    for item in &items {
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

        // Decrypt the inline envelope
        let enc_blob_str = item["encrypted_blob"].as_str().unwrap_or("");
        if enc_blob_str.is_empty() {
            continue;
        }
        let blob_data = STANDARD.decode(enc_blob_str).unwrap_or_default();
        if blob_data.len() < 25 {
            continue;
        }

        let decrypted =
            match vault_core::envelope::decrypt_blob_bytes(&blob_data, &item_key, &user_id) {
                Ok(d) => d,
                Err(_) => continue,
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
        vault_core::client::unwrap_owned_item_key(master_key, &user_id, fwk, fn_).unwrap_or_else(
            |e| {
                eprintln!("error unwrapping file key: {}", e);
                std::process::exit(1);
            },
        )
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

    // Decrypt file blob
    let decrypted = vault_core::envelope::decrypt_blob_bytes(&file_blob_data, &file_key, &user_id)
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
