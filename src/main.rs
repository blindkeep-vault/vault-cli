use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use clap::{Parser, Subcommand};
use hkdf::Hkdf;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};
use std::path::PathBuf;
use vault_core::crypto::{decrypt_item, encrypt_item};

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
    /// Encrypt and upload a file as an anonymous drop
    Drop {
        /// File to encrypt and upload
        file: PathBuf,
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
        Some(Command::Drop { file }) => {
            run_drop_upload(&client, &cli.api_url, &file);
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

            let version = drop_meta["drop_key_version"].as_i64().unwrap_or(1) as i32;
            eprintln!("Deriving wrapping key (v{})...", version);
            let wrapping_key = derive_drop_wrapping_key(&mnemonic, version);
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

fn derive_drop_wrapping_key(mnemonic: &str, version: i32) -> [u8; 32] {
    let iterations = if version >= 2 { 600_000 } else { 2048 };
    let mut out = [0u8; 32];
    pbkdf2::<Hmac<Sha512>>(mnemonic.as_bytes(), b"vault-drop", iterations, &mut out)
        .expect("PBKDF2 failed");
    out
}

fn wrap_drop_key(wrapping_key: &[u8; 32], drop_key: &[u8; 32]) -> Vec<u8> {
    let enc = encrypt_item(wrapping_key, drop_key).expect("wrap failed");
    let mut out = Vec::with_capacity(24 + enc.ciphertext.len());
    out.extend_from_slice(&enc.nonce);
    out.extend_from_slice(&enc.ciphertext);
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

fn padded_size(actual: usize) -> usize {
    let total = 4 + actual;
    if total <= 1024 {
        return 1024;
    }
    if total <= 16384 {
        let mut s = 1024;
        while s < total {
            s *= 2;
        }
        return s;
    }
    if total <= 1_048_576 {
        return total.div_ceil(65536) * 65536;
    }
    if total <= 67_108_864 {
        return total.div_ceil(1_048_576) * 1_048_576;
    }
    total.div_ceil(8_388_608) * 8_388_608
}

fn pad_plaintext(data: &[u8]) -> Vec<u8> {
    let target = padded_size(data.len());
    let mut result = vec![0u8; target];
    let len = data.len() as u32;
    result[..4].copy_from_slice(&len.to_be_bytes());
    result[4..4 + data.len()].copy_from_slice(data);
    // Fill padding with random bytes
    if target > 4 + data.len() {
        rand::rngs::OsRng.fill_bytes(&mut result[4 + data.len()..]);
    }
    result
}

fn generate_bip39_mnemonic() -> String {
    use bip39::Mnemonic;
    let mut entropy = [0u8; 16]; // 128 bits → 12 words
    rand::rngs::OsRng.fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy(&entropy).expect("mnemonic generation failed");
    mnemonic.to_string()
}

fn run_drop_upload(client: &reqwest::blocking::Client, api_url: &str, file_path: &std::path::Path) {
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
    let wrapped_drop_key = wrap_drop_key(&wrapping_key, &drop_key);

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

    // Upload blob to S3
    let put_resp = client
        .put(upload_url)
        .body(blob.clone())
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: upload failed: {}", e);
            std::process::exit(1);
        });
    if !put_resp.status().is_success() {
        eprintln!("error: upload failed ({})", put_resp.status());
        std::process::exit(1);
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
