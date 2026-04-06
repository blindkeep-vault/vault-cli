use super::*;

pub fn run_billing_balance(client: &reqwest::blocking::Client, api_url: &str, json: bool) {
    let session = load_session().unwrap_or_else(|| {
        eprintln!("error: not logged in");
        std::process::exit(1);
    });

    let resp = client
        .get(format!("{}/billing/balance", api_url))
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

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&body).expect("serialize")
        );
        return;
    }

    let balance = body["gb_year_balance"].as_f64().unwrap_or(0.0);
    let burn_rate = body["burn_rate_gb"].as_f64().unwrap_or(0.0);
    let est_years = body["estimated_years_remaining"].as_f64();

    println!("Balance:     {:.4} GB·years", balance);
    println!("Burn rate:   {:.6} GB", burn_rate);
    if let Some(y) = est_years {
        if y > 0.0 {
            println!("Est. remaining: {:.1} years", y);
        }
    }
    if let Some(grace) = body["grace_expires_at"].as_str() {
        println!("Grace expires: {}", grace);
    }
}

pub fn run_billing_history(client: &reqwest::blocking::Client, api_url: &str, json: bool) {
    let session = load_session().unwrap_or_else(|| {
        eprintln!("error: not logged in");
        std::process::exit(1);
    });

    let resp = client
        .get(format!("{}/billing/history", api_url))
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

    let entries: Vec<serde_json::Value> = resp.json().expect("invalid JSON");

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&entries).expect("serialize")
        );
        return;
    }

    if entries.is_empty() {
        eprintln!("No billing history.");
        return;
    }

    println!("{:<22} {:>14} PAYMENT ID", "DATE", "MB·HOURS");
    println!("{}", "-".repeat(60));
    for entry in &entries {
        let date = entry["created_at"]
            .as_str()
            .map(|s| if s.len() >= 10 { &s[..10] } else { s })
            .unwrap_or("?");
        let mbhours = entry["mbhours_added"].as_f64().unwrap_or(0.0);
        let payment = entry["stripe_payment_id"].as_str().unwrap_or("-");
        println!("{:<22} {:>14.1} {}", date, mbhours, payment);
    }
}
