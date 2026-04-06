use super::*;

pub fn run_deadman(
    client: &reqwest::blocking::Client,
    api_url: &str,
    action: crate::DeadmanAction,
) {
    match action {
        crate::DeadmanAction::Enable { interval } => run_enable(client, api_url, interval),
        crate::DeadmanAction::Status => run_status(client, api_url),
        crate::DeadmanAction::Checkin => run_checkin(client, api_url),
        crate::DeadmanAction::Disable => run_disable(client, api_url),
    }
}

fn run_enable(client: &reqwest::blocking::Client, api_url: &str, interval_days: u32) {
    if !(7..=365).contains(&interval_days) {
        eprintln!("error: interval must be between 7 and 365 days");
        std::process::exit(1);
    }

    let session = load_session().unwrap_or_else(|| {
        eprintln!("error: not logged in");
        std::process::exit(1);
    });

    let resp = client
        .post(format!("{}/deadman", api_url))
        .header("Authorization", format!("Bearer {}", session.jwt))
        .json(&serde_json::json!({ "interval_days": interval_days }))
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

    eprintln!("Deadman switch enabled (interval: {} days).", interval_days);
    eprintln!("Run `vault-cli deadman checkin` regularly to reset the timer.");
}

fn run_status(client: &reqwest::blocking::Client, api_url: &str) {
    let session = load_session().unwrap_or_else(|| {
        eprintln!("error: not logged in");
        std::process::exit(1);
    });

    let resp = client
        .get(format!("{}/deadman", api_url))
        .header("Authorization", format!("Bearer {}", session.jwt))
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

    let body: serde_json::Value = resp.json().expect("invalid JSON");

    let enabled = body["deadman_enabled"].as_bool().unwrap_or(false);
    if !enabled {
        println!("Deadman switch: disabled");
        return;
    }

    println!("Deadman switch: enabled");
    if let Some(interval) = body["deadman_interval_days"].as_i64() {
        println!("Interval:       {} days", interval);
    }
    if let Some(checkin) = body["last_checkin_at"].as_str() {
        println!("Last check-in:  {}", checkin);
    }
}

fn run_checkin(client: &reqwest::blocking::Client, api_url: &str) {
    let session = load_session().unwrap_or_else(|| {
        eprintln!("error: not logged in");
        std::process::exit(1);
    });

    let resp = client
        .post(format!("{}/deadman/checkin", api_url))
        .header("Authorization", format!("Bearer {}", session.jwt))
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

    eprintln!("Deadman check-in recorded.");
}

fn run_disable(client: &reqwest::blocking::Client, api_url: &str) {
    let session = load_session().unwrap_or_else(|| {
        eprintln!("error: not logged in");
        std::process::exit(1);
    });

    let resp = client
        .delete(format!("{}/deadman", api_url))
        .header("Authorization", format!("Bearer {}", session.jwt))
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

    eprintln!("Deadman switch disabled.");
}
