use super::*;
use uuid::Uuid;
use vault_core::merkle::{leaf_hash, verify_inclusion};

// --- Helpers ---

/// Resolve a log name to its UUID by listing the caller's logs and matching
/// on `name`. v0 has no `?name=` lookup endpoint — `list_logs` is cheap and
/// keeps the server contract minimal. Exits non-zero on no match.
fn resolve_log_id(vc: &VaultClient, name: &str) -> Uuid {
    let rows: Vec<serde_json::Value> = vc
        .get("/event-logs")
        .json()
        .unwrap_or_else(|e| fatal(&format!("invalid /event-logs response: {e}")));
    for row in &rows {
        if row["name"].as_str() == Some(name) {
            let id_str = row["id"].as_str().unwrap_or_default();
            return Uuid::parse_str(id_str).unwrap_or_else(|_| {
                fatal(&format!("server returned invalid log id for '{name}'"))
            });
        }
    }
    fatal(&format!("log '{name}' not found"));
}

/// Read `--event` arg in the same shape as `decision --rationale`: a literal
/// JSON string, `@path` for a file, or stdin if absent. Always parses to a
/// `serde_json::Value` so the CLI surfaces malformed input before sending.
fn read_event_arg(arg: Option<&str>) -> serde_json::Value {
    let raw = match arg {
        Some(v) if v.starts_with('@') => std::fs::read_to_string(&v[1..]).unwrap_or_else(|e| {
            fatal(&format!("error reading {}: {e}", &v[1..]));
        }),
        Some(v) => v.to_string(),
        None => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .unwrap_or_else(|e| fatal(&format!("error reading stdin: {e}")));
            buf
        }
    };
    serde_json::from_str(&raw).unwrap_or_else(|e| fatal(&format!("event is not valid JSON: {e}")))
}

fn fatal(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}

// --- create ---

pub fn run_create(
    client: &reqwest::blocking::Client,
    api_url: &str,
    name: &str,
    schema_uri: Option<&str>,
    signing_pubkey_hex: Option<&str>,
    rate_limit_per_min: Option<i32>,
) {
    let auth = get_auth(client, api_url);
    let vc = VaultClient::from_auth(&auth);

    let mut body = serde_json::json!({ "name": name });
    if let Some(s) = schema_uri {
        body["schema_uri"] = serde_json::json!(s);
    }
    if let Some(s) = signing_pubkey_hex {
        body["signing_pubkey"] = serde_json::json!(s);
    }
    if let Some(r) = rate_limit_per_min {
        body["rate_limit_per_min"] = serde_json::json!(r);
    }

    let row: serde_json::Value = vc
        .post_json("/event-logs", &body)
        .json()
        .unwrap_or_else(|e| fatal(&format!("invalid response: {e}")));

    println!("Created event log:");
    println!("  id:    {}", row["id"].as_str().unwrap_or("?"));
    println!("  name:  {}", row["name"].as_str().unwrap_or("?"));
    if let Some(s) = row["schema_uri"].as_str() {
        println!("  schema_uri: {s}");
    }
    if let Some(s) = row["signing_pubkey"].as_str() {
        println!("  signing_pubkey: {s}");
    }
    println!(
        "  rate_limit_per_min: {}",
        row["rate_limit_per_min"].as_i64().unwrap_or(0)
    );
}

// --- list ---

pub fn run_list(client: &reqwest::blocking::Client, api_url: &str) {
    let auth = get_auth(client, api_url);
    let vc = VaultClient::from_auth(&auth);

    let rows: Vec<serde_json::Value> = vc
        .get("/event-logs")
        .json()
        .unwrap_or_else(|e| fatal(&format!("invalid response: {e}")));

    if rows.is_empty() {
        eprintln!("No event logs.");
        return;
    }

    println!("{:<38} {:<24} {:<10}", "ID", "NAME", "RATE/MIN");
    println!("{}", "-".repeat(74));
    for r in &rows {
        println!(
            "{:<38} {:<24} {:<10}",
            r["id"].as_str().unwrap_or("?"),
            r["name"].as_str().unwrap_or("?"),
            r["rate_limit_per_min"].as_i64().unwrap_or(0),
        );
    }
}

// --- append ---

pub fn run_append(
    client: &reqwest::blocking::Client,
    api_url: &str,
    name: &str,
    event_arg: Option<&str>,
    sig_hex: Option<&str>,
    save_cert: bool,
) {
    let event = read_event_arg(event_arg);

    let auth = get_auth(client, api_url);
    let vc = VaultClient::from_auth(&auth);
    let log_id = resolve_log_id(&vc, name);

    let mut body = serde_json::json!({ "event": event });
    if let Some(s) = sig_hex {
        body["client_signature"] = serde_json::json!(s);
    }

    let resp: serde_json::Value = vc
        .post_json(&format!("/event-logs/{log_id}/entries"), &body)
        .json()
        .unwrap_or_else(|e| fatal(&format!("invalid response: {e}")));

    let seq = resp["seq"].as_i64().unwrap_or(0);
    let entry_id = resp["id"].as_str().unwrap_or("?");
    let tree_index = resp["tree_index"].as_i64().unwrap_or(0);
    let tree_root_hex = resp["tree_root"].as_str().unwrap_or("");

    eprintln!("Appended seq={seq} entry_id={entry_id}");
    eprintln!("  tree_index: {tree_index}");
    eprintln!("  tree_root:  {tree_root_hex}");

    if save_cert {
        // Reuse the entry-proof cert shape so `vault-cli log verify --cert
        // <path>` (single-entry verification) can consume it without a
        // server round-trip. The append response already contains
        // everything the proof endpoint returns, plus the payload echoed
        // back from the request — assemble the cert locally.
        let cert = serde_json::json!({
            "version": 1,
            "kind": "event_log_entry",
            "log": { "id": log_id.to_string(), "name": name },
            "entry": {
                "id": entry_id,
                "seq": seq,
                "payload_hash": resp["payload_hash"],
                "payload": event,
                "client_signature": sig_hex,
                "timestamp": resp["timestamp"],
                "timestamp_millis": resp["timestamp_millis"],
            },
            "tree": {
                "index": tree_index,
                "size": resp["tree_size"],
                "root": tree_root_hex,
            },
            "inclusion_proof": resp["inclusion_proof"],
            "server_signature": resp["server_signature"],
            "signing_key": resp["signing_key"],
        });
        let path = format!("event-{}-{seq}.json", &log_id.to_string()[..8]);
        std::fs::write(&path, serde_json::to_vec_pretty(&cert).unwrap())
            .unwrap_or_else(|e| fatal(&format!("error writing {path}: {e}")));
        eprintln!("  certificate: {path}");
    }

    // Always print the seq on stdout so it can be captured in pipelines.
    println!("{seq}");
}

// --- entries (list) ---

pub fn run_entries(
    client: &reqwest::blocking::Client,
    api_url: &str,
    name: &str,
    from: Option<i64>,
    to: Option<i64>,
    limit: Option<i64>,
) {
    let auth = get_auth(client, api_url);
    let vc = VaultClient::from_auth(&auth);
    let log_id = resolve_log_id(&vc, name);

    let from_seq = from.unwrap_or(1).max(1);
    let mut path = format!("/event-logs/{log_id}/entries?from_seq={from_seq}");
    if let Some(l) = limit {
        path.push_str(&format!("&limit={l}"));
    }
    let rows: Vec<serde_json::Value> = vc
        .get(&path)
        .json()
        .unwrap_or_else(|e| fatal(&format!("invalid response: {e}")));

    let to_seq = to.unwrap_or(i64::MAX);
    for r in &rows {
        let seq = r["seq"].as_i64().unwrap_or(0);
        if seq > to_seq {
            break;
        }
        let ts = r["timestamp"].as_str().unwrap_or("?");
        println!("seq={seq} ts={ts}");
        println!(
            "  payload: {}",
            serde_json::to_string(&r["payload"]).unwrap_or_default()
        );
    }
}

// --- verify ---

/// Walk seq from `--from` to `--to`, fetching the inclusion-proof certificate
/// for each entry, recomputing the leaf hash, and calling `verify_inclusion`
/// offline. Also enforces contiguity (every seq in [from, to] is present)
/// and reports per-entry pass/fail.
pub fn run_verify(
    client: &reqwest::blocking::Client,
    api_url: &str,
    name: &str,
    from: i64,
    to: i64,
) {
    if to < from {
        fatal("--to must be >= --from");
    }
    let auth = get_auth(client, api_url);
    let vc = VaultClient::from_auth(&auth);
    let log_id = resolve_log_id(&vc, name);

    let mut all_pass = true;
    for seq in from..=to {
        let path = format!("/event-logs/{log_id}/entries/{seq}/proof");
        let cert: serde_json::Value = match vc.get(&path).json::<serde_json::Value>() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("seq={seq} [FAIL] could not fetch proof: {e}");
                all_pass = false;
                continue;
            }
        };

        let entry_id_str = cert["entry"]["id"].as_str().unwrap_or("");
        let entry_id = match Uuid::parse_str(entry_id_str) {
            Ok(u) => u,
            Err(_) => {
                eprintln!("seq={seq} [FAIL] cert has invalid entry.id");
                all_pass = false;
                continue;
            }
        };

        let payload_hash_hex = cert["entry"]["payload_hash"].as_str().unwrap_or("");
        let payload_hash: [u8; 32] = match hex::decode(payload_hash_hex) {
            Ok(b) if b.len() == 32 => b.as_slice().try_into().unwrap(),
            _ => {
                eprintln!("seq={seq} [FAIL] cert has invalid payload_hash");
                all_pass = false;
                continue;
            }
        };
        let timestamp_ms = cert["entry"]["timestamp_millis"].as_i64().unwrap_or(0);

        let tree_index = cert["tree"]["index"].as_i64().unwrap_or(0);
        let tree_size = cert["tree"]["size"].as_i64().unwrap_or(0);
        let tree_root_hex = cert["tree"]["root"].as_str().unwrap_or("");
        let tree_root: [u8; 32] = match hex::decode(tree_root_hex) {
            Ok(b) if b.len() == 32 => b.as_slice().try_into().unwrap(),
            _ => {
                eprintln!("seq={seq} [FAIL] cert has invalid tree.root");
                all_pass = false;
                continue;
            }
        };
        let proof: Vec<Vec<u8>> = cert["inclusion_proof"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|h| h.as_str().and_then(|s| hex::decode(s).ok()))
                    .collect()
            })
            .unwrap_or_default();

        let leaf = leaf_hash(entry_id, &payload_hash, None, timestamp_ms);
        let inclusion_ok = verify_inclusion(&leaf, tree_index, tree_size, &proof, &tree_root);

        // Server-signature check (Ed25519 over payload_hash || 0u8*32 || ts || root).
        let sig_b64 = cert["server_signature"].as_str().unwrap_or("");
        let sig = STANDARD.decode(sig_b64).unwrap_or_default();
        let key_b64 = cert["signing_key"].as_str().unwrap_or("");
        let key = STANDARD.decode(key_b64).unwrap_or_default();
        let sig_ok = if sig.len() == 64 && key.len() == 32 {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&key);
            let mut s = [0u8; 64];
            s.copy_from_slice(&sig);
            vault_core::crypto::verify_notarization_signature(
                &pk,
                &payload_hash,
                None,
                timestamp_ms,
                &tree_root,
                &s,
            )
        } else {
            false
        };

        if inclusion_ok && sig_ok {
            println!("seq={seq} [PASS]");
        } else {
            println!(
                "seq={seq} [FAIL] inclusion={} signature={}",
                inclusion_ok, sig_ok
            );
            all_pass = false;
        }
    }

    if all_pass {
        eprintln!("All {} entries verified.", to - from + 1);
    } else {
        std::process::exit(1);
    }
}

// --- delete ---

pub fn run_delete(client: &reqwest::blocking::Client, api_url: &str, name: &str, yes: bool) {
    let auth = get_auth(client, api_url);
    let vc = VaultClient::from_auth(&auth);
    let log_id = resolve_log_id(&vc, name);

    if !yes {
        eprintln!("Delete log '{name}' ({log_id})?");
        eprintln!("  Existing inclusion-proof certificates remain valid against historical roots,");
        eprintln!("  but the server will no longer answer queries for this log's entries.");
        let line = prompt_line("Type the log name to confirm: ");
        if line != name {
            fatal("name did not match — aborting");
        }
    }

    vc.delete(&format!("/event-logs/{log_id}"));
    eprintln!("Deleted log '{name}'.");
}
