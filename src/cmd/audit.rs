use super::*;

pub fn run_audit(
    client: &reqwest::blocking::Client,
    api_url: &str,
    resource_type: Option<&str>,
    limit: Option<i64>,
    json: bool,
) {
    let session = load_session().unwrap_or_else(|| {
        eprintln!("error: not logged in");
        std::process::exit(1);
    });

    let mut params = Vec::new();
    if let Some(rt) = resource_type {
        params.push(("resource_type", rt.to_string()));
    }
    if let Some(n) = limit {
        params.push(("limit", n.to_string()));
    }

    let resp = client
        .get(format!("{}/audit-log", api_url))
        .header("Authorization", format!("Bearer {}", session.jwt))
        .query(&params)
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

    let entries: Vec<serde_json::Value> = resp.json().expect("invalid JSON");

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&entries).expect("serialize")
        );
        return;
    }

    if entries.is_empty() {
        eprintln!("No audit log entries found.");
        return;
    }

    println!(
        "{:<22} {:<24} {:<12} {:<38} IP",
        "TIMESTAMP", "ACTION", "RESOURCE", "RESOURCE ID"
    );
    println!("{}", "-".repeat(100));
    for entry in &entries {
        let ts = entry["created_at"]
            .as_str()
            .map(|s| if s.len() >= 19 { &s[..19] } else { s })
            .unwrap_or("?");
        println!(
            "{:<22} {:<24} {:<12} {:<38} {}",
            ts,
            entry["action"].as_str().unwrap_or("?"),
            entry["resource_type"].as_str().unwrap_or("?"),
            entry["resource_id"].as_str().unwrap_or("?"),
            entry["ip_address"].as_str().unwrap_or("-"),
        );
    }
}
