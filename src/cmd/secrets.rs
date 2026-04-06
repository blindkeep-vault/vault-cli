use super::*;

pub fn run_put(
    client: &reqwest::blocking::Client,
    api_url: &str,
    label: &str,
    value: Option<&str>,
) {
    let auth = get_auth(client, api_url);

    let secret_value = match value {
        Some(v) if v.starts_with('@') => {
            let path = &v[1..];
            std::fs::read_to_string(path).unwrap_or_else(|e| {
                eprintln!("error reading {}: {}", path, e);
                std::process::exit(1);
            })
        }
        Some(v) => v.to_string(),
        None => {
            let mut buf = String::new();
            std::io::stdin().read_line(&mut buf).unwrap_or_else(|e| {
                eprintln!("error reading stdin: {}", e);
                std::process::exit(1);
            });
            buf.trim_end().to_string()
        }
    };

    let blob = SecretBlob {
        name: label.to_string(),
        content: Some(secret_value),
        label: None,
        item_type: None,
        value: None,
        filename: None,
        mime_type: None,
        file_size: None,
        file_wrapped_key: None,
        file_nonce: None,
    };
    let blob_json = serde_json::to_vec(&blob).expect("serialize blob");

    // Generate random item key
    let mut item_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut item_key);

    let user_id = load_session().map(|s| s.user_id).unwrap_or_default();

    // Encrypt blob with item key (V1 with AAD)
    let blob_aad = format!("item:{}", user_id);
    let enc_blob = vault_core::crypto::encrypt_item_v1(&item_key, &blob_json, blob_aad.as_bytes())
        .unwrap_or_else(|e| {
            eprintln!("error encrypting: {}", e);
            std::process::exit(1);
        });

    // Build blob: 0x01 + nonce(24) + ciphertext (V1 concat format)
    let mut blob_data = Vec::with_capacity(1 + 24 + enc_blob.ciphertext.len());
    blob_data.push(0x01);
    blob_data.extend_from_slice(&enc_blob.nonce);
    blob_data.extend_from_slice(&enc_blob.ciphertext);
    let blob_b64 = STANDARD.encode(&blob_data);

    // Wrap item key with encryption subkey (V1 with AAD)
    let master_key = match &auth {
        AuthContext::Full { master_key, .. } => master_key,
        AuthContext::Scoped { .. } => {
            eprintln!("error: scoped API keys cannot create items");
            std::process::exit(1);
        }
    };
    let enc_key = derive_subkey(master_key, b"vault-enc").unwrap_or_else(|e| {
        eprintln!("error: {}", e);
        std::process::exit(1);
    });
    let wrap_aad = format!("wrap:{}", user_id);
    let wrapped = vault_core::crypto::encrypt_item_v1(&enc_key, &item_key, wrap_aad.as_bytes())
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });

    let resp = client
        .post(format!("{}/items", auth.api_url()))
        .header("Authorization", format!("Bearer {}", auth.jwt()))
        .json(&serde_json::json!({
            "encrypted_blob": blob_b64,
            "wrapped_key": wrapped.ciphertext,
            "nonce": wrapped.nonce.to_vec(),
            "item_type": "encrypted",
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

    eprintln!("Secret '{}' stored.", label);
}

pub fn run_get(
    client: &reqwest::blocking::Client,
    api_url: &str,
    label: &str,
    output: Option<PathBuf>,
) {
    let auth = get_auth(client, api_url);
    let secrets = fetch_and_decrypt_secrets(client, &auth);

    let found = secrets
        .iter()
        .find(|(_, blob, _)| blob.display_name() == label);
    match found {
        Some((_, blob, _)) => {
            if blob.is_file() {
                eprintln!("'{}' is a file:", label);
                if let Some(f) = &blob.filename {
                    eprintln!("  Filename: {}", f);
                }
                if let Some(m) = &blob.mime_type {
                    eprintln!("  Type:     {}", m);
                }
                if let Some(s) = blob.file_size {
                    if s >= 1_048_576 {
                        eprintln!("  Size:     {:.1} MB", s as f64 / 1_048_576.0);
                    } else if s >= 1024 {
                        eprintln!("  Size:     {:.1} KB", s as f64 / 1024.0);
                    } else {
                        eprintln!("  Size:     {} bytes", s);
                    }
                }
                eprintln!();
                eprintln!("To download: vault-cli file get \"{}\"", label);
                std::process::exit(1);
            }
            if let Some(path) = output {
                std::fs::write(&path, blob.secret_value().unwrap_or("")).unwrap_or_else(|e| {
                    eprintln!("error writing {}: {}", path.display(), e);
                    std::process::exit(1);
                });
                eprintln!("Written to {}", path.display());
            } else {
                print!("{}", blob.secret_value().unwrap_or(""));
            }
        }
        None => {
            eprintln!("error: secret '{}' not found", label);
            std::process::exit(1);
        }
    }
}

pub fn run_ls(client: &reqwest::blocking::Client, api_url: &str, prefix: Option<&str>) {
    let auth = get_auth(client, api_url);
    let secrets = fetch_and_decrypt_secrets(client, &auth);

    let filtered: Vec<_> = secrets
        .iter()
        .filter(|(_, blob, _)| match prefix {
            Some(p) => blob.display_name().starts_with(p),
            None => true,
        })
        .collect();

    if filtered.is_empty() {
        eprintln!("No secrets found.");
        return;
    }

    for (_, blob, _) in &filtered {
        if blob.is_file() {
            println!("[file] {}", blob.display_name());
        } else {
            println!("{}", blob.display_name());
        }
    }
}

pub fn run_rm(client: &reqwest::blocking::Client, api_url: &str, label: &str) {
    let auth = get_auth(client, api_url);
    let secrets = fetch_and_decrypt_secrets(client, &auth);

    let found = secrets
        .iter()
        .find(|(_, blob, _)| blob.display_name() == label);
    match found {
        Some((item_id, _, _)) => {
            let resp = client
                .delete(format!("{}/items/{}", auth.api_url(), item_id))
                .header("Authorization", format!("Bearer {}", auth.jwt()))
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

            eprintln!("Secret '{}' deleted.", label);
        }
        None => {
            eprintln!("error: secret '{}' not found", label);
            std::process::exit(1);
        }
    }
}
