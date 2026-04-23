use super::*;

pub fn run_put(
    client: &reqwest::blocking::Client,
    api_url: &str,
    label: &str,
    value: Option<&str>,
    one_shot_retrievable: bool,
    notarize_on_use: bool,
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

    let master_key = match &auth {
        AuthContext::Full { master_key, .. } => master_key,
        AuthContext::Scoped { .. } => {
            eprintln!("error: scoped API keys cannot create items");
            std::process::exit(1);
        }
    };

    let user_id = load_session().map(|s| s.user_id).unwrap_or_default();
    let prepared =
        vault_core::client::prepare_item_create(master_key, &user_id, label, &secret_value, None)
            .unwrap_or_else(|e| {
                eprintln!("error encrypting: {}", e);
                std::process::exit(1);
            });

    let mut body = serde_json::json!({
        "encrypted_blob": prepared.encrypted_blob_b64,
        "wrapped_key": prepared.wrapped_key,
        "nonce": prepared.nonce.to_vec(),
        "item_type": "encrypted",
    });
    if one_shot_retrievable {
        body["one_shot"] = serde_json::json!(true);
    }
    if notarize_on_use {
        body["notarize_on_use"] = serde_json::json!(true);
    }

    let vc = VaultClient::from_auth(&auth);
    vc.post_json("/items", &body);

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
        Some((_, blob, raw_item)) => {
            let has_file_blob = serde_json::from_str::<serde_json::Value>(raw_item)
                .ok()
                .and_then(|v| v["file_blob_key"].as_str().map(|s| !s.is_empty()))
                .unwrap_or(false);
            if blob.is_file() || has_file_blob || blob.filename.is_some() {
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
            let vc = VaultClient::from_auth(&auth);
            vc.delete(&format!("/items/{}", item_id));
            eprintln!("Secret '{}' deleted.", label);
        }
        None => {
            eprintln!("error: secret '{}' not found", label);
            std::process::exit(1);
        }
    }
}
