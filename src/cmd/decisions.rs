use super::*;

/// Record a notarized approval-decision (issue #5). The rationale is
/// encrypted client-side with the caller's master key — same envelope
/// shape as `secrets put` — so even the BlindKeep operator can't read it.
/// The structured fields (`action`, `target`, `approver`, `supersedes`)
/// land plaintext on the server because they drive the GET /decisions
/// filter API; equality filters need plaintext.
#[allow(clippy::too_many_arguments)]
pub fn run_record(
    client: &reqwest::blocking::Client,
    api_url: &str,
    action: &str,
    target: &str,
    rationale: Option<&str>,
    approver: Option<&str>,
    supersedes: Option<&str>,
    decided_at: Option<&str>,
) {
    let auth = get_auth(client, api_url);

    // Rationale: explicit string, @file path, or stdin (matches `secrets put`).
    let rationale_text = match rationale {
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
            std::io::stdin()
                .read_to_string(&mut buf)
                .unwrap_or_else(|e| {
                    eprintln!("error reading stdin: {}", e);
                    std::process::exit(1);
                });
            buf.trim_end().to_string()
        }
    };

    let master_key = match &auth {
        AuthContext::Full { master_key, .. } => master_key,
        AuthContext::Scoped { .. } => {
            eprintln!("error: scoped API keys cannot record decisions");
            std::process::exit(1);
        }
    };

    let user_id = load_session().map(|s| s.user_id).unwrap_or_default();
    // Label is the human-facing name shown by `vault-cli ls`. Action and
    // target are anyway plaintext on the server; encoding them here keeps
    // the owner's local view scannable.
    let label = format!("decision: {action} -> {target}");
    let prepared = vault_core::client::prepare_item_create(
        master_key,
        &user_id,
        &label,
        &rationale_text,
        None,
    )
    .unwrap_or_else(|e| {
        eprintln!("error encrypting: {}", e);
        std::process::exit(1);
    });

    let mut body = serde_json::json!({
        "encrypted_blob": prepared.encrypted_blob_b64,
        "wrapped_key": prepared.wrapped_key,
        "nonce": prepared.nonce.to_vec(),
        "action": action,
        "target": target,
    });
    if let Some(a) = approver {
        body["approver"] = serde_json::json!(a);
    }
    if let Some(s) = supersedes {
        body["supersedes"] = serde_json::json!(s);
    }
    if let Some(d) = decided_at {
        body["decided_at"] = serde_json::json!(d);
    }

    let vc = VaultClient::from_auth(&auth);
    let result: serde_json::Value = vc
        .post_json("/decisions", &body)
        .json()
        .expect("invalid JSON");

    let id = result["id"].as_str().unwrap_or("?");
    let approver_out = result["approver"].as_str().unwrap_or("?");
    let notarization_id = result["notarization"]["id"].as_str().unwrap_or("?");
    let timestamp = result["notarization"]["timestamp"].as_str().unwrap_or("?");

    eprintln!("Decision recorded:");
    eprintln!("  ID:           {}", id);
    eprintln!("  Action:       {}", action);
    eprintln!("  Target:       {}", target);
    eprintln!("  Approver:     {}", approver_out);
    if let Some(s) = supersedes {
        eprintln!("  Supersedes:   {}", s);
    }
    eprintln!(
        "  Decided at:   {}",
        result["decided_at"].as_str().unwrap_or("?")
    );
    eprintln!("  Notarization: {}", notarization_id);
    eprintln!("  Timestamp:    {}", timestamp);
}

/// Fetch a single decision by id. Structured fields + anchoring
/// notarization; use `vault-cli notarize verify <cert.json>` downstream if
/// the caller wants to validate the signature against the server's public
/// key.
pub fn run_show(client: &reqwest::blocking::Client, api_url: &str, id: &str, json_out: bool) {
    let auth = get_auth(client, api_url);
    let vc = VaultClient::from_auth(&auth);
    let result: serde_json::Value = vc
        .get(&format!("/decisions/{}", id))
        .json()
        .expect("invalid JSON");

    if json_out {
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
        return;
    }

    eprintln!("Decision:");
    eprintln!("  ID:           {}", result["id"].as_str().unwrap_or("?"));
    eprintln!(
        "  Action:       {}",
        result["action"].as_str().unwrap_or("?")
    );
    eprintln!(
        "  Target:       {}",
        result["target"].as_str().unwrap_or("?")
    );
    eprintln!(
        "  Approver:     {}",
        result["approver"].as_str().unwrap_or("?")
    );
    if let Some(s) = result["supersedes"].as_str() {
        eprintln!("  Supersedes:   {}", s);
    }
    eprintln!(
        "  Decided at:   {}",
        result["decided_at"].as_str().unwrap_or("?")
    );
    if let Some(n) = result["notarization"].as_object() {
        eprintln!("  Notarization:");
        eprintln!(
            "    ID:         {}",
            n.get("id").and_then(|v| v.as_str()).unwrap_or("?")
        );
        eprintln!(
            "    Timestamp:  {}",
            n.get("timestamp").and_then(|v| v.as_str()).unwrap_or("?")
        );
        eprintln!(
            "    Hash:       {}",
            n.get("content_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
        );
    } else {
        eprintln!("  Notarization: (not linked)");
    }
}

/// Query the decision log with optional filters. The server returns the
/// rows and a *receipt* — a notarization whose `content_hash` is the
/// canonical hash of the filter parameters and the result set. A consumer
/// can replay the query later, recompute the hash via
/// `vault_core::decisions::canonical_query_result_hash`, and verify the
/// signed receipt to prove the set has not been silently truncated.
#[allow(clippy::too_many_arguments)]
pub fn run_query(
    client: &reqwest::blocking::Client,
    api_url: &str,
    approver: Option<&str>,
    action: Option<&str>,
    target: Option<&str>,
    since: Option<&str>,
    until: Option<&str>,
    supersedes: Option<&str>,
    limit: Option<i64>,
    offset: Option<i64>,
    json_out: bool,
) {
    let auth = get_auth(client, api_url);

    // Build query params via reqwest's serializer for proper URL escaping.
    let mut params: Vec<(&str, String)> = Vec::new();
    if let Some(v) = approver {
        params.push(("approver", v.to_string()));
    }
    if let Some(v) = action {
        params.push(("action", v.to_string()));
    }
    if let Some(v) = target {
        params.push(("target", v.to_string()));
    }
    if let Some(v) = since {
        params.push(("since", v.to_string()));
    }
    if let Some(v) = until {
        params.push(("until", v.to_string()));
    }
    if let Some(v) = supersedes {
        params.push(("supersedes", v.to_string()));
    }
    if let Some(v) = limit {
        params.push(("limit", v.to_string()));
    }
    if let Some(v) = offset {
        params.push(("offset", v.to_string()));
    }

    let vc = VaultClient::from_auth(&auth);
    let result: serde_json::Value = vc
        .get_query("/decisions", &params)
        .json()
        .expect("invalid JSON");

    if json_out {
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
        return;
    }

    let empty = Vec::new();
    let decisions = result["decisions"].as_array().unwrap_or(&empty);

    if decisions.is_empty() {
        eprintln!("No decisions match the filter.");
    } else {
        println!(
            "{:<38} {:<26} {:<16} {:<24} APPROVER",
            "ID", "DECIDED_AT", "ACTION", "TARGET"
        );
        println!("{}", "-".repeat(120));
        for d in decisions {
            let id = d["id"].as_str().unwrap_or("?");
            let decided_at = d["decided_at"].as_str().unwrap_or("?");
            let action = d["action"].as_str().unwrap_or("?");
            let target = d["target"].as_str().unwrap_or("?");
            let approver = d["approver"].as_str().unwrap_or("?");
            let action_short = truncate(action, 16);
            let target_short = truncate(target, 24);
            println!(
                "{:<38} {:<26} {:<16} {:<24} {}",
                id, decided_at, action_short, target_short, approver
            );
        }
    }

    eprintln!();
    eprintln!("Receipt:");
    eprintln!(
        "  Notarization: {}",
        result["receipt"]["notarization_id"].as_str().unwrap_or("?")
    );
    eprintln!(
        "  Timestamp:    {}",
        result["receipt"]["timestamp"].as_str().unwrap_or("?")
    );
    eprintln!(
        "  Content hash: {}",
        result["receipt"]["content_hash"].as_str().unwrap_or("?")
    );
    eprintln!("  Returned:     {} row(s)", decisions.len());
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let head: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{head}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_keeps_short_strings() {
        assert_eq!(truncate("short", 16), "short");
    }

    #[test]
    fn truncate_marks_overflow() {
        assert_eq!(truncate("0123456789abcdef", 8), "0123456…");
    }

    #[test]
    fn truncate_handles_unicode() {
        // Chars, not bytes — a 2-byte UTF-8 char must count as one.
        let s = "résumé-very-long-string";
        let out = truncate(s, 5);
        assert_eq!(out.chars().count(), 5);
    }
}
