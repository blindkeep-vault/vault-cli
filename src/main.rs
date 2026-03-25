use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use clap::{Parser, Subcommand};
use hkdf::Hkdf;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::{Digest, Sha256, Sha512};
use std::path::PathBuf;
use vault_core::crypto::decrypt_item;

#[derive(Parser)]
#[command(
    name = "vault-cli",
    about = "BlindKeep vault CLI — download drops, notarize documents, verify certificates"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// API base URL
    #[arg(
        long,
        env = "VAULT_API_URL",
        default_value = "https://blindkeep.com",
        global = true
    )]
    api_url: String,

    // Legacy positional args for backwards compat (drop download)
    /// Drop key or mnemonic (legacy usage: vault-cli KEY [KEY2])
    key: Option<String>,
    key2: Option<String>,

    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Download and decrypt a drop (same as legacy positional args)
    Download {
        key: String,
        key2: Option<String>,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Notarize a file or hash
    Notarize {
        /// File to notarize or hex SHA-256 hash
        input: String,
        /// JWT token
        #[arg(long, env = "VAULT_TOKEN")]
        token: String,
        /// Item ID to link
        #[arg(long)]
        item_id: Option<String>,
        /// Output certificate file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Verify a notarization certificate
    Verify {
        /// Certificate JSON file
        certificate: PathBuf,
        /// Optional document to verify hash against
        document: Option<PathBuf>,
    },
    /// List notarizations
    Notarizations {
        /// JWT token
        #[arg(long, env = "VAULT_TOKEN")]
        token: String,
    },
}

enum ParsedInput {
    Direct {
        drop_id: String,
        key: [u8; 32],
    },
    Mnemonic {
        mnemonic: String,
        drop_id: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    let client = reqwest::blocking::Client::new();

    match cli.command {
        Some(Command::Download { key, key2, output }) => {
            run_drop_download(&client, &cli.api_url, &key, key2.as_deref(), output);
        }
        Some(Command::Notarize {
            input,
            token,
            item_id,
            output,
        }) => {
            run_notarize(
                &client,
                &cli.api_url,
                &token,
                &input,
                item_id.as_deref(),
                output,
            );
        }
        Some(Command::Verify {
            certificate,
            document,
        }) => {
            run_verify(&certificate, document.as_deref());
        }
        Some(Command::Notarizations { token }) => {
            run_list_notarizations(&client, &cli.api_url, &token);
        }
        None => {
            // Legacy: positional args for drop download
            if let Some(key) = cli.key {
                run_drop_download(&client, &cli.api_url, &key, cli.key2.as_deref(), cli.output);
            } else {
                eprintln!("Usage: vault-cli <COMMAND> or vault-cli <KEY> [KEY2]");
                eprintln!("  Commands: download, notarize, verify, notarizations");
                std::process::exit(1);
            }
        }
    }
}

fn run_notarize(
    client: &reqwest::blocking::Client,
    api_url: &str,
    token: &str,
    input: &str,
    item_id: Option<&str>,
    output: Option<PathBuf>,
) {
    // Determine if input is a hex hash or a file path
    let content_hash = if input.len() == 64 && input.chars().all(|c| c.is_ascii_hexdigit()) {
        input.to_string()
    } else {
        let path = PathBuf::from(input);
        if !path.exists() {
            eprintln!("error: '{}' is not a file or a 64-char hex hash", input);
            std::process::exit(1);
        }
        eprintln!("Hashing {}...", input);
        let data = std::fs::read(&path).unwrap_or_else(|e| {
            eprintln!("error reading {}: {}", input, e);
            std::process::exit(1);
        });
        let hash = Sha256::digest(&data);
        hex::encode(hash)
    };

    eprintln!("Content hash: {}", content_hash);

    let mut body = serde_json::json!({ "content_hash": content_hash });
    if let Some(id) = item_id {
        body["item_id"] = serde_json::Value::String(id.to_string());
    }

    let resp = client
        .post(format!("{}/notarizations", api_url))
        .header("Authorization", format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .expect("request failed");

    if !resp.status().is_success() {
        let text = resp.text().unwrap_or_default();
        eprintln!("error: notarization failed: {}", text);
        std::process::exit(1);
    }

    let result: serde_json::Value = resp.json().expect("invalid JSON");
    let notarization_id = result["id"].as_str().unwrap();
    eprintln!("Notarization created: {}", notarization_id);

    // Fetch certificate
    let cert_resp = client
        .get(format!(
            "{}/notarizations/{}/certificate",
            api_url, notarization_id
        ))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .expect("certificate request failed");

    if !cert_resp.status().is_success() {
        eprintln!("warning: could not fetch certificate");
        return;
    }

    let cert: serde_json::Value = cert_resp.json().expect("invalid certificate JSON");
    let cert_json = serde_json::to_string_pretty(&cert).unwrap();

    let out_path = output
        .unwrap_or_else(|| PathBuf::from(format!("notarization-{}.json", &notarization_id[..8])));
    std::fs::write(&out_path, &cert_json).unwrap_or_else(|e| {
        eprintln!("error writing {}: {}", out_path.display(), e);
        std::process::exit(1);
    });
    eprintln!("Certificate saved to {}", out_path.display());
}

fn run_verify(certificate_path: &std::path::Path, document: Option<&std::path::Path>) {
    let cert_json = std::fs::read_to_string(certificate_path).unwrap_or_else(|e| {
        eprintln!("error reading {}: {}", certificate_path.display(), e);
        std::process::exit(1);
    });
    let cert: serde_json::Value = serde_json::from_str(&cert_json).unwrap_or_else(|e| {
        eprintln!("error parsing certificate: {}", e);
        std::process::exit(1);
    });

    // 1. Verify document hash if provided
    if let Some(doc_path) = document {
        let data = std::fs::read(doc_path).unwrap_or_else(|e| {
            eprintln!("error reading {}: {}", doc_path.display(), e);
            std::process::exit(1);
        });
        let hash = Sha256::digest(&data);
        let hash_hex = hex::encode(hash);
        let cert_hash = cert["content_hash"].as_str().unwrap_or("");
        if hash_hex == cert_hash {
            eprintln!("[PASS] Document hash matches certificate");
        } else {
            eprintln!("[FAIL] Document hash mismatch");
            eprintln!("  Document: {}", hash_hex);
            eprintln!("  Certificate: {}", cert_hash);
        }
    }

    // 2. Verify Ed25519 signature
    let content_hash_hex = cert["content_hash"].as_str().unwrap_or("");
    let content_hash = hex::decode(content_hash_hex).unwrap_or_default();
    let tree_root_hex = cert["tree_root"].as_str().unwrap_or("");
    let tree_root = hex::decode(tree_root_hex).unwrap_or_default();
    let timestamp_millis = cert["timestamp_millis"].as_i64().unwrap_or(0);
    let signature_b64 = cert["signature"].as_str().unwrap_or("");
    let signature = STANDARD.decode(signature_b64).unwrap_or_default();
    let signing_key_b64 = cert["signing_key"].as_str().unwrap_or("");
    let signing_key = STANDARD.decode(signing_key_b64).unwrap_or_default();

    if content_hash.len() == 32
        && tree_root.len() == 32
        && signature.len() == 64
        && signing_key.len() == 32
    {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&signing_key);
        let mut ch = [0u8; 32];
        ch.copy_from_slice(&content_hash);
        let mut tr = [0u8; 32];
        tr.copy_from_slice(&tree_root);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&signature);

        if vault_core::crypto::verify_notarization_signature(&pk, &ch, timestamp_millis, &tr, &sig)
        {
            eprintln!("[PASS] Ed25519 signature valid");
        } else {
            eprintln!("[FAIL] Ed25519 signature invalid");
        }
    } else {
        eprintln!("[FAIL] Invalid certificate field lengths");
    }

    // 3. Print metadata
    eprintln!();
    eprintln!(
        "Notarization ID: {}",
        cert["notarization_id"].as_str().unwrap_or("?")
    );
    eprintln!("Timestamp: {}", cert["timestamp"].as_str().unwrap_or("?"));
    eprintln!(
        "Tree index: {} / size: {}",
        cert["tree_index"], cert["tree_size"]
    );
    if let Some(anchors) = cert["anchors"].as_array() {
        if !anchors.is_empty() {
            eprintln!("Anchors: {} RFC 3161 anchor(s)", anchors.len());
        }
    }
}

fn run_list_notarizations(client: &reqwest::blocking::Client, api_url: &str, token: &str) {
    let resp = client
        .get(format!("{}/notarizations", api_url))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .expect("request failed");

    if !resp.status().is_success() {
        let text = resp.text().unwrap_or_default();
        eprintln!("error: {}", text);
        std::process::exit(1);
    }

    let rows: Vec<serde_json::Value> = resp.json().expect("invalid JSON");
    if rows.is_empty() {
        eprintln!("No notarizations found.");
        return;
    }

    println!("{:<38} {:<26} {:<18}", "ID", "TIMESTAMP", "HASH (short)");
    println!("{}", "-".repeat(82));
    for r in &rows {
        let id = r["id"].as_str().unwrap_or("?");
        let ts = r["timestamp"].as_str().unwrap_or("?");
        let hash = r["content_hash"].as_str().unwrap_or("?");
        let hash_short = if hash.len() > 16 { &hash[..16] } else { hash };
        println!("{:<38} {:<26} {}...", id, ts, hash_short);
    }
}

fn run_drop_download(
    client: &reqwest::blocking::Client,
    api_url: &str,
    key: &str,
    key2: Option<&str>,
    output: Option<PathBuf>,
) {
    let parsed = parse_input(key, key2);

    match parsed {
        ParsedInput::Direct { drop_id, key } => {
            download_drop(client, api_url, &drop_id, &key, output);
        }
        ParsedInput::Mnemonic { mnemonic, drop_id } => {
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

            eprintln!("Deriving wrapping key...");
            let wrapping_key = derive_drop_wrapping_key(&mnemonic);
            let drop_key = unwrap_drop_key(&wrapping_key, &wrapped_bytes);

            download_drop(client, api_url, &resolved_id, &drop_key, output);
        }
    }
}

fn parse_input(key: &str, key2: Option<&str>) -> ParsedInput {
    let input = key.trim();

    if let Some(k2) = key2 {
        let k2 = k2.trim();
        if looks_like_uuid(input) {
            if let Some(key_bytes) = try_decode_base64url(k2) {
                return ParsedInput::Direct {
                    drop_id: input.to_string(),
                    key: key_bytes,
                };
            }
        }
        if looks_like_uuid(k2) {
            if let Some(key_bytes) = try_decode_base64url(input) {
                return ParsedInput::Direct {
                    drop_id: k2.to_string(),
                    key: key_bytes,
                };
            }
        }
        let combined = format!("{} {}", input, k2);
        return parse_input(&combined, None);
    }

    if let Some(caps) = extract_drop_url(input) {
        return ParsedInput::Direct {
            drop_id: caps.0,
            key: caps.1,
        };
    }

    if let Some(slug) = extract_pickup_slug(input) {
        let mnemonic = slug.replace('-', " ");
        return ParsedInput::Mnemonic {
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
        return ParsedInput::Mnemonic {
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
        return ParsedInput::Mnemonic {
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

fn looks_like_uuid(s: &str) -> bool {
    uuid::Uuid::parse_str(s).is_ok()
}

fn try_decode_base64url(s: &str) -> Option<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD.decode(s).ok()?;
    if bytes.len() == 32 {
        Some(bytes.try_into().unwrap())
    } else {
        None
    }
}

fn extract_drop_url(s: &str) -> Option<(String, [u8; 32])> {
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

fn extract_pickup_slug(s: &str) -> Option<String> {
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

fn extract_pickup_uuid(s: &str) -> Option<String> {
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

fn download_drop(
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

fn unpad(data: &[u8]) -> &[u8] {
    if data.len() < 4 {
        return data;
    }
    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if len > data.len() - 4 {
        return data;
    }
    &data[4..4 + len]
}

fn parse_envelope<'a>(data: &'a [u8], drop_id: &str) -> (String, &'a [u8]) {
    if data.len() > 4 {
        let header_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if header_len > 0 && header_len < 10240 && 4 + header_len <= data.len() {
            if let Ok(meta_json) = std::str::from_utf8(&data[4..4 + header_len]) {
                if let Ok(meta) = serde_json::from_str::<serde_json::Value>(meta_json) {
                    let name = meta["name"]
                        .as_str()
                        .unwrap_or(&format!("drop-{}", &drop_id[..8]))
                        .to_string();
                    return (name, &data[4 + header_len..]);
                }
            }
        }
    }
    (format!("drop-{}", &drop_id[..8.min(drop_id.len())]), data)
}

fn normalize_mnemonic(m: &str) -> String {
    m.split_whitespace()
        .map(|w| w.to_lowercase())
        .collect::<Vec<_>>()
        .join(" ")
}

fn derive_drop_lookup_key(mnemonic: &str) -> String {
    let hkdf = Hkdf::<Sha256>::new(Some(b"vault-drop"), mnemonic.as_bytes());
    let mut out = [0u8; 32];
    hkdf.expand(b"lookup", &mut out)
        .expect("HKDF expand failed");
    hex::encode(out)
}

fn derive_drop_wrapping_key(mnemonic: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2::<Hmac<Sha512>>(mnemonic.as_bytes(), b"vault-drop", 2048, &mut out)
        .expect("PBKDF2 failed");
    out
}

fn unwrap_drop_key(wrapping_key: &[u8; 32], wrapped: &[u8]) -> [u8; 32] {
    if wrapped.len() < 25 {
        eprintln!("error: wrapped_drop_key too short");
        std::process::exit(1);
    }
    let nonce = &wrapped[..24];
    let ciphertext = &wrapped[24..];
    let plain = decrypt_item(wrapping_key, ciphertext, nonce).unwrap_or_else(|e| {
        eprintln!("error: failed to unwrap drop key (wrong mnemonic?): {}", e);
        std::process::exit(1);
    });
    if plain.len() != 32 {
        eprintln!("error: unwrapped key is {} bytes, expected 32", plain.len());
        std::process::exit(1);
    }
    let bytes: [u8; 32] = plain.as_slice().try_into().unwrap();
    bytes
}
