use super::*;

pub fn run_inbox(_client: &reqwest::blocking::Client, api_url: &str, action: crate::InboxAction) {
    match action {
        crate::InboxAction::Create { slug, label } => {
            run_create(api_url, slug.as_deref(), label.as_deref())
        }
        crate::InboxAction::List { json } => run_list(api_url, json),
        crate::InboxAction::Delete { id } => run_delete(api_url, &id),
        crate::InboxAction::Info { id } => run_info(api_url, &id),
    }
}

fn run_create(api_url: &str, slug: Option<&str>, label: Option<&str>) {
    let session = load_session().unwrap_or_else(|| {
        eprintln!("error: not logged in");
        std::process::exit(1);
    });

    let vc = VaultClient::new(api_url, &session.jwt);

    let mut body = serde_json::json!({});
    if let Some(s) = slug {
        body["slug"] = serde_json::json!(s);
    }
    if let Some(l) = label {
        body["label"] = serde_json::json!(l);
    }

    let result: serde_json::Value = vc
        .post_json("/dead-drop-inboxes", &body)
        .json()
        .expect("invalid JSON");
    let id = result["id"].as_str().unwrap_or("?");
    let inbox_slug = result["slug"].as_str();

    eprintln!("Inbox created: {}", id);
    if let Some(s) = inbox_slug {
        eprintln!("Slug: {}", s);
    }
}

fn run_list(api_url: &str, json: bool) {
    let session = load_session().unwrap_or_else(|| {
        eprintln!("error: not logged in");
        std::process::exit(1);
    });

    let vc = VaultClient::new(api_url, &session.jwt);
    let inboxes: Vec<serde_json::Value> =
        vc.get("/dead-drop-inboxes").json().expect("invalid JSON");

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&inboxes).expect("serialize")
        );
        return;
    }

    if inboxes.is_empty() {
        eprintln!("No inboxes found.");
        return;
    }

    println!("{:<38} {:<20} {:<8} LABEL", "ID", "SLUG", "ACTIVE");
    println!("{}", "-".repeat(80));
    for inbox in &inboxes {
        println!(
            "{:<38} {:<20} {:<8} {}",
            inbox["id"].as_str().unwrap_or("?"),
            inbox["slug"].as_str().unwrap_or("-"),
            if inbox["active"].as_bool().unwrap_or(false) {
                "yes"
            } else {
                "no"
            },
            inbox["label"].as_str().unwrap_or(""),
        );
    }
}

fn run_delete(api_url: &str, id: &str) {
    let session = load_session().unwrap_or_else(|| {
        eprintln!("error: not logged in");
        std::process::exit(1);
    });

    let vc = VaultClient::new(api_url, &session.jwt);
    vc.delete(&format!("/dead-drop-inboxes/{}", id));
    eprintln!("Inbox {} deleted.", id);
}

fn run_info(api_url: &str, id_or_slug: &str) {
    // This is an unauthenticated endpoint
    let vc = VaultClient::new(api_url, "");
    let resp = vc.get_unauth_raw(&format!("/dead-drop-inboxes/{}/info", id_or_slug));

    if !resp.status().is_success() {
        if resp.status().as_u16() == 404 {
            eprintln!("error: inbox not found or inactive");
        } else {
            let text = resp.text().unwrap_or_default();
            eprintln!("error: {}", text);
        }
        std::process::exit(1);
    }

    let body: serde_json::Value = resp.json().expect("invalid JSON");
    println!(
        "{}",
        serde_json::to_string_pretty(&body).expect("serialize")
    );
}
