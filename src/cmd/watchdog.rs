use super::*;

pub fn run_watchdog(
    _client: &reqwest::blocking::Client,
    api_url: &str,
    action: crate::WatchdogAction,
) {
    match action {
        crate::WatchdogAction::Register {
            interval,
            tolerance,
            label,
        } => run_register(api_url, &interval, tolerance.as_deref(), label.as_deref()),
        crate::WatchdogAction::Ping { id } => run_ping(api_url, &id),
        crate::WatchdogAction::Query { json } => run_query(api_url, json),
        crate::WatchdogAction::Delete { id } => run_delete(api_url, &id),
    }
}

fn run_register(api_url: &str, interval: &str, tolerance: Option<&str>, label: Option<&str>) {
    let interval_secs = parse_duration_secs(interval).unwrap_or_else(|e| {
        eprintln!("error: invalid --interval: {e}");
        std::process::exit(1);
    });
    let tolerance_secs = tolerance
        .map(|t| {
            parse_duration_secs(t).unwrap_or_else(|e| {
                eprintln!("error: invalid --tolerance: {e}");
                std::process::exit(1);
            })
        })
        .unwrap_or(0);

    let session = load_session().unwrap_or_else(|| {
        eprintln!("error: not logged in");
        std::process::exit(1);
    });

    let vc = VaultClient::new(api_url, &session.jwt);
    let mut body = serde_json::json!({
        "interval_secs": interval_secs,
        "tolerance_secs": tolerance_secs,
    });
    if let Some(l) = label {
        body["label"] = serde_json::Value::String(l.to_string());
    }
    let resp: serde_json::Value = vc
        .post_json("/watchdog", &body)
        .json()
        .expect("invalid JSON");

    let id = resp["id"].as_str().unwrap_or("<unknown>");
    eprintln!("Watchdog registered: {id}");
    eprintln!("  interval:  {interval_secs}s");
    eprintln!("  tolerance: {tolerance_secs}s");
    eprintln!();
    eprintln!("Run `vault-cli watchdog ping {id}` within every interval to keep it alive.");
}

fn run_ping(api_url: &str, id: &str) {
    let session = load_session().unwrap_or_else(|| {
        eprintln!("error: not logged in");
        std::process::exit(1);
    });

    let vc = VaultClient::new(api_url, &session.jwt);
    let resp: serde_json::Value = vc
        .post_json(&format!("/watchdog/{id}/ping"), &serde_json::json!({}))
        .json()
        .expect("invalid JSON");

    let counter = resp["counter"].as_i64().unwrap_or_default();
    let ping_at = resp["ping_at"].as_str().unwrap_or("");
    let tree_index = resp["attestation"]["tree_index"]
        .as_i64()
        .unwrap_or_default();

    eprintln!("Watchdog {id} ping recorded.");
    eprintln!("  counter:     {counter}");
    eprintln!("  ping_at:     {ping_at}");
    eprintln!("  tree_index:  {tree_index}");
}

fn run_query(api_url: &str, as_json: bool) {
    let session = load_session().unwrap_or_else(|| {
        eprintln!("error: not logged in");
        std::process::exit(1);
    });

    let vc = VaultClient::new(api_url, &session.jwt);
    let resp: serde_json::Value = vc.get("/watchdog").json().expect("invalid JSON");

    if as_json {
        println!("{}", serde_json::to_string_pretty(&resp).unwrap());
        return;
    }

    let sessions = resp.as_array().cloned().unwrap_or_default();
    if sessions.is_empty() {
        println!("No watchdog sessions registered.");
        return;
    }

    for s in &sessions {
        let id = s["id"].as_str().unwrap_or("<?>");
        let label = s["label"].as_str().unwrap_or("-");
        let interval = s["interval_secs"].as_i64().unwrap_or_default();
        let tolerance = s["tolerance_secs"].as_i64().unwrap_or_default();
        let counter = s["counter"].as_i64().unwrap_or_default();
        let last_ping = s["last_ping_at"].as_str().unwrap_or("-");
        let lost_at = s["lost_at"].as_str();

        println!("{id}");
        println!("  label:     {label}");
        println!("  interval:  {interval}s (± {tolerance}s)");
        println!("  counter:   {counter}");
        println!("  last ping: {last_ping}");
        match lost_at {
            Some(t) => println!("  LOST at:   {t}"),
            None => println!("  status:    live"),
        }
        println!();
    }
}

fn run_delete(api_url: &str, id: &str) {
    let session = load_session().unwrap_or_else(|| {
        eprintln!("error: not logged in");
        std::process::exit(1);
    });

    let vc = VaultClient::new(api_url, &session.jwt);
    vc.delete(&format!("/watchdog/{id}"));

    eprintln!("Watchdog {id} deleted.");
}

/// Accept a bare integer (seconds) or a suffixed form like `30s`/`5m`/`2h`/`1d`.
/// Bare negative integers are rejected up front; `parse_duration` itself
/// never yields a negative value.
fn parse_duration_secs(s: &str) -> Result<i32, String> {
    if let Ok(n) = s.parse::<i32>() {
        if n < 0 {
            return Err("negative duration".into());
        }
        return Ok(n);
    }
    let dur = vault_core::util::parse_duration(s).map_err(|e| e.to_string())?;
    let secs = dur.num_seconds();
    i32::try_from(secs).map_err(|_| format!("duration {secs}s exceeds i32 range"))
}
