//! `vault-cli tombstone <scope-tag>` — issue #7's atomic scope revocation.
//!
//! Thin wrapper around `POST /scopes/tombstone`: validate the tag client-
//! side (same `validate_scope_tag` the server runs, so an obviously bad
//! tag fails before a round-trip), parse the optional retention duration,
//! POST, print the summary. The server is the source of truth for counts,
//! state, and retention boundary — this command just surfaces what came
//! back.

use super::*;

pub fn run_tombstone(
    _client: &reqwest::blocking::Client,
    api_url: &str,
    scope_tag: &str,
    retention: Option<&str>,
    reason: Option<&str>,
) {
    if let Err(e) = vault_core::validate_scope_tag(scope_tag) {
        eprintln!("error: invalid scope tag: {e}");
        std::process::exit(1);
    }

    let session = load_session().unwrap_or_else(|| {
        eprintln!("error: not logged in. Run `vault-cli login` first");
        std::process::exit(1);
    });

    let vc = VaultClient::new(api_url, &session.jwt);

    let mut body = serde_json::json!({ "scope_tag": scope_tag });
    if let Some(ret) = retention {
        let duration = parse_duration(ret).unwrap_or_else(|err| {
            eprintln!("error: --retention: {err}");
            std::process::exit(1);
        });
        // The server takes `retention_days`, not a duration string, so a
        // fractional-day input (e.g. `12h`) rounds up to the next full
        // day. Sub-day retention collapses to zero otherwise, and the
        // server clamps zero up to its MIN_RETENTION_DAYS of 1 — surfacing
        // the rounding here keeps the CLI / server retention window
        // readable to the caller.
        let seconds = duration.num_seconds().max(0);
        let days = ((seconds + 86_399) / 86_400).max(1) as u32;
        body["retention_days"] = serde_json::json!(days);
    }
    if let Some(r) = reason {
        body["reason"] = serde_json::json!(r);
    }

    let resp = vc.post_json_raw("/scopes/tombstone", &body);
    let status = resp.status();
    let text = resp.text().unwrap_or_default();

    if !status.is_success() {
        eprintln!("error ({}): {}", status, text);
        std::process::exit(1);
    }

    let result: serde_json::Value = serde_json::from_str(&text).unwrap_or_else(|e| {
        eprintln!("error: invalid response JSON: {e}");
        std::process::exit(1);
    });

    let was_new = status == reqwest::StatusCode::CREATED;
    if was_new {
        eprintln!("Scope '{scope_tag}' tombstoned.");
    } else {
        eprintln!("Scope '{scope_tag}' was already tombstoned; returning existing record.");
    }

    // Echo the server-persisted tag with a client-side revalidation — same
    // pattern as `apikey create` — so a misbehaving server can't smuggle
    // ANSI escapes into the terminal under our branding.
    if let Some(tag) = result["scope_tag"]
        .as_str()
        .filter(|t| vault_core::validate_scope_tag(t).is_ok())
    {
        eprintln!("Tag: {tag}");
    }
    eprintln!("State: {}", result["state"].as_str().unwrap_or("?"));
    if let Some(reason) = result["reason"].as_str() {
        eprintln!("Reason: {reason}");
    }
    eprintln!(
        "Retention expires: {}",
        result["retention_expires_at"].as_str().unwrap_or("?")
    );
    eprintln!(
        "Revoked: {} grant(s), {} api key(s), {} api-key grant(s); {} item(s) frozen",
        result["grants_revoked"].as_i64().unwrap_or(0),
        result["api_keys_revoked"].as_i64().unwrap_or(0),
        result["api_key_grants_revoked"].as_i64().unwrap_or(0),
        result["items_frozen"].as_i64().unwrap_or(0),
    );
    if let Some(notar) = result.get("notarization").and_then(|n| n.as_object()) {
        if let Some(id) = notar.get("id").and_then(|v| v.as_str()) {
            eprintln!("Notarization: {id}");
        }
    }
}
