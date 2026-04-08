use super::*;

pub fn parse_dotenv(content: &str) -> Vec<(String, String)> {
    let mut vars = Vec::new();
    let mut lines = content.lines().peekable();

    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Strip optional "export " prefix
        let trimmed = trimmed.strip_prefix("export ").unwrap_or(trimmed);

        let Some(eq_pos) = trimmed.find('=') else {
            eprintln!("warning: skipping malformed line: {}", trimmed);
            continue;
        };

        let key = trimmed[..eq_pos].trim().to_string();
        let raw_value = &trimmed[eq_pos + 1..];

        let value = if let Some(dq_inner) = raw_value.strip_prefix('"') {
            // Double-quoted: handle escapes, may span multiple lines
            let mut buf = dq_inner.to_string();
            while !buf.ends_with('"') || buf.ends_with("\\\"") {
                if let Some(next_line) = lines.next() {
                    buf.push('\n');
                    buf.push_str(next_line);
                } else {
                    break;
                }
            }
            // Remove trailing quote
            if buf.ends_with('"') {
                buf.pop();
            }
            // Process escapes
            buf.replace("\\n", "\n")
                .replace("\\\"", "\"")
                .replace("\\\\", "\\")
        } else if let Some(sq_inner) = raw_value.strip_prefix('\'') {
            // Single-quoted: literal, no escapes
            let inner = sq_inner.strip_suffix('\'').unwrap_or(sq_inner);
            inner.to_string()
        } else {
            // Unquoted: strip inline comments
            let value = if let Some(comment_pos) = raw_value.find(" #") {
                &raw_value[..comment_pos]
            } else {
                raw_value
            };
            value.trim().to_string()
        };

        if key.is_empty() {
            continue;
        }
        vars.push((key, value));
    }

    vars
}

pub fn find_envfile<'a>(
    secrets: &'a [(String, SecretBlob, String)],
    label: &str,
) -> Option<&'a (String, SecretBlob, String)> {
    secrets.iter().find(|(_, blob, _)| {
        blob.display_name() == label && blob.item_type.as_deref() == Some("envfile")
    })
}

pub fn run_env_push(client: &reqwest::blocking::Client, api_url: &str, label: &str, file: &str) {
    let content = if file == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .unwrap_or_else(|e| {
                eprintln!("error reading stdin: {}", e);
                std::process::exit(1);
            });
        buf
    } else {
        std::fs::read_to_string(file).unwrap_or_else(|e| {
            eprintln!("error reading {}: {}", file, e);
            std::process::exit(1);
        })
    };

    // Validate the .env content parses correctly
    let vars = parse_dotenv(&content);
    eprintln!(
        "Parsed {} variables from {}",
        vars.len(),
        if file == "-" { "stdin" } else { file }
    );

    let auth = get_auth(client, api_url);
    let vc = VaultClient::from_auth(&auth);

    // Check if envfile already exists, delete it first
    let secrets = fetch_and_decrypt_secrets(client, &auth);
    if let Some((item_id, _, _)) = find_envfile(&secrets, label) {
        vc.delete(&format!("/items/{}", item_id));
    }

    // Create the envfile item
    let master_key = match &auth {
        AuthContext::Full { master_key, .. } => master_key,
        AuthContext::Scoped { .. } => {
            eprintln!("error: scoped API keys cannot create items");
            std::process::exit(1);
        }
    };

    let user_id = load_session().map(|s| s.user_id).unwrap_or_default();
    let prepared = vault_core::client::prepare_item_create(
        master_key,
        &user_id,
        label,
        &content,
        Some("envfile"),
    )
    .unwrap_or_else(|e| {
        eprintln!("error encrypting: {}", e);
        std::process::exit(1);
    });

    vc.post_json(
        "/items",
        &serde_json::json!({
            "encrypted_blob": prepared.encrypted_blob_b64,
            "wrapped_key": prepared.wrapped_key,
            "nonce": prepared.nonce.to_vec(),
            "item_type": "encrypted",
        }),
    );

    eprintln!("Env file '{}' stored ({} variables).", label, vars.len());
}

pub fn run_env_pull(
    client: &reqwest::blocking::Client,
    api_url: &str,
    label: &str,
    output: Option<PathBuf>,
) {
    let auth = get_auth(client, api_url);
    let secrets = fetch_and_decrypt_secrets(client, &auth);

    match find_envfile(&secrets, label) {
        Some((_, blob, _)) => {
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
            eprintln!("error: env file '{}' not found", label);
            std::process::exit(1);
        }
    }
}

pub fn run_env_run(client: &reqwest::blocking::Client, api_url: &str, label: &str, cmd: &[String]) {
    if cmd.is_empty() {
        eprintln!("error: no command specified");
        std::process::exit(1);
    }

    let auth = get_auth(client, api_url);
    let secrets = fetch_and_decrypt_secrets(client, &auth);

    let (_, blob, _) = match find_envfile(&secrets, label) {
        Some(entry) => entry,
        None => {
            eprintln!("error: env file '{}' not found", label);
            std::process::exit(1);
        }
    };

    let env_vars = parse_dotenv(blob.secret_value().unwrap_or(""));

    let mut command = std::process::Command::new(&cmd[0]);
    command.args(&cmd[1..]);
    for (k, v) in &env_vars {
        command.env(k, v);
    }

    let status = command.status().unwrap_or_else(|e| {
        eprintln!("error: failed to run command: {}", e);
        std::process::exit(1);
    });

    std::process::exit(status.code().unwrap_or(1));
}

pub fn run_env_export(client: &reqwest::blocking::Client, api_url: &str, label: &str) {
    let auth = get_auth(client, api_url);
    let secrets = fetch_and_decrypt_secrets(client, &auth);

    let (_, blob, _) = match find_envfile(&secrets, label) {
        Some(entry) => entry,
        None => {
            eprintln!("error: env file '{}' not found", label);
            std::process::exit(1);
        }
    };

    let env_vars = parse_dotenv(blob.secret_value().unwrap_or(""));

    for (k, v) in &env_vars {
        // Validate env var name to prevent shell injection
        if k.is_empty()
            || k.starts_with(|c: char| c.is_ascii_digit())
            || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            eprintln!("warning: skipping invalid env var name: {}", k);
            continue;
        }
        // Shell-escape the value: wrap in single quotes, escape existing single quotes
        let escaped = v.replace('\'', "'\\''");
        println!("export {}='{}'", k, escaped);
    }
}

pub fn run_env(client: &reqwest::blocking::Client, api_url: &str, prefix: &str, cmd: &[String]) {
    if cmd.is_empty() {
        eprintln!("error: no command specified");
        std::process::exit(1);
    }

    let auth = get_auth(client, api_url);
    let secrets = fetch_and_decrypt_secrets(client, &auth);

    let matching: Vec<_> = secrets
        .iter()
        .filter(|(_, blob, _)| blob.display_name().starts_with(prefix))
        .collect();

    let mut env_vars: Vec<(String, String)> = Vec::new();
    for (_, blob, _) in &matching {
        let name = blob.display_name()[prefix.len()..]
            .to_uppercase()
            .replace(['/', '-'], "_");
        if name.is_empty() {
            continue;
        }
        env_vars.push((name, blob.secret_value().unwrap_or("").to_string()));
    }

    let mut command = std::process::Command::new(&cmd[0]);
    command.args(&cmd[1..]);
    for (k, v) in &env_vars {
        command.env(k, v);
    }

    let status = command.status().unwrap_or_else(|e| {
        eprintln!("error: failed to run command: {}", e);
        std::process::exit(1);
    });

    std::process::exit(status.code().unwrap_or(1));
}

// --- Existing commands ---
