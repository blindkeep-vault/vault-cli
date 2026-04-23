use super::*;

// --- Existing commands ---

pub fn run_notarize(
    _client: &reqwest::blocking::Client,
    api_url: &str,
    token: &str,
    input: &str,
    item_id: Option<&str>,
    output: Option<PathBuf>,
    rfc3161: bool,
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

    let vc = VaultClient::new(api_url, token);
    let result: serde_json::Value = vc
        .post_json("/notarizations", &body)
        .json()
        .expect("invalid JSON");

    let notarization_id = result["id"].as_str().unwrap();
    eprintln!("Notarization created: {}", notarization_id);

    // Fetch certificate
    let cert_resp = vc.get_raw(&format!("/notarizations/{}/certificate", notarization_id));

    if !cert_resp.status().is_success() {
        eprintln!("warning: could not fetch certificate");
        return;
    }

    let cert: serde_json::Value = cert_resp.json().expect("invalid certificate JSON");
    let cert_json = serde_json::to_string_pretty(&cert).unwrap();

    let out_path = default_cert_path(output, notarization_id);
    std::fs::write(&out_path, &cert_json).unwrap_or_else(|e| {
        eprintln!("error writing {}: {}", out_path.display(), e);
        std::process::exit(1);
    });
    eprintln!("Certificate saved to {}", out_path.display());

    if rfc3161 {
        let tsr_resp = vc.get_raw(&format!("/notarizations/{}/tsr", notarization_id));
        if !tsr_resp.status().is_success() {
            eprintln!(
                "warning: could not fetch RFC 3161 TSR (HTTP {})",
                tsr_resp.status()
            );
            return;
        }
        let tsr_bytes = tsr_resp.bytes().unwrap_or_else(|e| {
            eprintln!("error reading TSR body: {}", e);
            std::process::exit(1);
        });
        let tsr_path = out_path.with_extension("tsr");
        std::fs::write(&tsr_path, &tsr_bytes).unwrap_or_else(|e| {
            eprintln!("error writing {}: {}", tsr_path.display(), e);
            std::process::exit(1);
        });
        eprintln!("RFC 3161 TSR saved to {}", tsr_path.display());
        eprintln!();
        eprintln!("To verify:");
        eprintln!("  curl -s {}/notary/tsa-cert.pem > tsa.pem", api_url);
        eprintln!(
            "  openssl ts -verify -in {} -data <original-file> -CAfile tsa.pem",
            tsr_path.display()
        );
    }
}

pub fn run_verify(certificate_path: &std::path::Path, document: Option<&std::path::Path>) {
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

        if vault_core::crypto::verify_notarization_signature(
            &pk,
            &ch,
            None,
            timestamp_millis,
            &tr,
            &sig,
        ) {
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

pub fn run_list_notarizations(_client: &reqwest::blocking::Client, api_url: &str, token: &str) {
    let vc = VaultClient::new(api_url, token);
    let rows: Vec<serde_json::Value> = vc.get("/notarizations").json().expect("invalid JSON");

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

/// Resolve the JSON certificate path, defaulting to `notarization-<id8>.json`
/// and appending `.json` to any caller-supplied path with no extension — so
/// the JSON cert and the sibling `<stem>.tsr` (emitted via `with_extension`)
/// always share a stem.
fn default_cert_path(output: Option<PathBuf>, notarization_id: &str) -> PathBuf {
    let mut p = output
        .unwrap_or_else(|| PathBuf::from(format!("notarization-{}.json", &notarization_id[..8])));
    if p.extension().is_none() {
        p.set_extension("json");
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "abcdef0123456789";

    #[test]
    fn default_path_used_when_output_is_none() {
        assert_eq!(
            default_cert_path(None, ID),
            PathBuf::from("notarization-abcdef01.json")
        );
    }

    #[test]
    fn extensionless_output_gets_json_appended() {
        assert_eq!(
            default_cert_path(Some(PathBuf::from("/tmp/foo")), ID),
            PathBuf::from("/tmp/foo.json")
        );
    }

    #[test]
    fn explicit_json_extension_is_unchanged() {
        assert_eq!(
            default_cert_path(Some(PathBuf::from("/tmp/foo.json")), ID),
            PathBuf::from("/tmp/foo.json")
        );
    }

    #[test]
    fn non_json_extension_is_respected() {
        assert_eq!(
            default_cert_path(Some(PathBuf::from("/tmp/foo.pdf")), ID),
            PathBuf::from("/tmp/foo.pdf")
        );
    }

    #[test]
    fn tsr_sibling_shares_stem_for_extensionless_output() {
        // Regression for #23: stems must match between JSON and TSR.
        let cert = default_cert_path(Some(PathBuf::from("/tmp/foo")), ID);
        let tsr = cert.with_extension("tsr");
        assert_eq!(cert.file_stem(), tsr.file_stem());
    }
}
