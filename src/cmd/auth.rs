use super::*;

pub fn run_register(_client: &reqwest::blocking::Client, api_url: &str) {
    let email = prompt_line("Email: ");
    let password = prompt_password("Password: ");
    let password2 = prompt_password("Confirm password: ");

    if password != password2 {
        eprintln!("error: passwords do not match");
        std::process::exit(1);
    }

    if password.len() < 12 {
        eprintln!("error: password must be at least 12 characters");
        std::process::exit(1);
    }

    eprintln!("Deriving keys...");
    let reg = vault_core::client::prepare_registration(&password).unwrap_or_else(|e| {
        eprintln!("error: key derivation failed: {}", e);
        std::process::exit(1);
    });

    let vc = VaultClient::new(api_url, "");

    eprintln!("Registering...");
    let auth: serde_json::Value = vc
        .post_json_unauth(
            "/auth/register",
            &serde_json::json!({
                "email": email,
                "auth_key": reg.auth_key_hex,
                "public_key": reg.public_key.to_vec(),
                "encrypted_private_key": reg.encrypted_private_key,
                "client_salt": reg.client_salt,
            }),
        )
        .json()
        .expect("invalid JSON");

    let jwt = auth["token"].as_str().expect("missing token").to_string();
    let user_id = auth["user_id"]
        .as_str()
        .expect("missing user_id")
        .to_string();

    save_session(&Session {
        api_url: api_url.to_string(),
        jwt,
        email: email.clone(),
        user_id,
        client_salt: reg.client_salt,
    });

    eprintln!("Registered and logged in as {}", email);
}

pub fn run_login(client: &reqwest::blocking::Client, api_url: &str) {
    let email = prompt_line("Email: ");

    let vc = VaultClient::new(api_url, "");

    // Get client_salt
    let params_resp =
        vc.post_json_unauth_raw("/auth/client-params", &serde_json::json!({"email": email}));

    if !params_resp.status().is_success() {
        eprintln!("error: failed to get client params");
        std::process::exit(1);
    }

    let params: serde_json::Value = params_resp.json().expect("invalid JSON");
    let client_salt: Vec<u8> = params["client_salt"]
        .as_array()
        .expect("missing client_salt")
        .iter()
        .map(|v| v.as_u64().unwrap() as u8)
        .collect();

    let password = prompt_password("Password: ");

    eprintln!("Deriving keys...");
    let login_payload =
        vault_core::client::prepare_login(&password, &client_salt).unwrap_or_else(|e| {
            eprintln!("error: key derivation failed: {}", e);
            std::process::exit(1);
        });

    let login_resp = vc.post_json_unauth_raw(
        "/auth/login",
        &serde_json::json!({
            "email": email,
            "auth_key": login_payload.auth_key_hex,
        }),
    );

    if !login_resp.status().is_success() {
        let text = login_resp.text().unwrap_or_default();
        eprintln!("error: login failed: {}", text);
        std::process::exit(1);
    }

    let auth: serde_json::Value = login_resp.json().expect("invalid JSON");
    let jwt = auth["token"].as_str().expect("missing token").to_string();
    let user_id = auth["user_id"]
        .as_str()
        .expect("missing user_id")
        .to_string();

    let session = Session {
        api_url: api_url.to_string(),
        jwt,
        email: email.clone(),
        user_id,
        client_salt,
    };

    save_session(&session);

    // Start agent (if not already running) and cache credentials so
    // subsequent commands don't re-prompt for the password — like sudo.
    crate::agent::run_start_quiet(30);
    let master_key = unwrap_master_key_from_profile(client, &session, &login_payload.master_key);
    crate::agent::try_store(
        &session.jwt,
        &master_key,
        &session.api_url,
        &session.user_id,
    );

    eprintln!("Logged in as {}", email);
}

pub fn run_change_password(client: &reqwest::blocking::Client, _api_url: &str) {
    let session = load_session().unwrap_or_else(|| {
        eprintln!("error: not logged in. Run `vault-cli login` first.");
        std::process::exit(1);
    });

    let current_password = prompt_password("Current password: ");
    let new_password = prompt_password("New password: ");
    let new_password2 = prompt_password("Confirm new password: ");

    if new_password != new_password2 {
        eprintln!("error: new passwords do not match");
        std::process::exit(1);
    }

    if new_password.len() < 12 {
        eprintln!("error: password must be at least 12 characters");
        std::process::exit(1);
    }

    if current_password == new_password {
        eprintln!("error: new password must be different from current password");
        std::process::exit(1);
    }

    // Derive current keys and unwrap master key
    eprintln!("Deriving current keys...");
    let current_login = vault_core::client::prepare_login(&current_password, &session.client_salt)
        .unwrap_or_else(|e| {
            eprintln!("error: key derivation failed: {}", e);
            std::process::exit(1);
        });

    let master_key = unwrap_master_key_from_profile(client, &session, &current_login.master_key);

    let vc = VaultClient::new(&session.api_url, &session.jwt);

    // Fetch profile to get encrypted_private_key and public_key
    let me_resp = vc.get_raw("/auth/me");
    if !me_resp.status().is_success() {
        eprintln!("error: session expired, please login again");
        std::process::exit(1);
    }
    let me: serde_json::Value = me_resp.json().expect("invalid JSON");
    let public_key = json_to_bytes(&me["public_key"]);
    let encrypted_privkey = json_to_bytes(&me["encrypted_private_key"]);

    eprintln!("Deriving new keys...");
    let change = vault_core::client::prepare_password_change(
        &current_password,
        &new_password,
        &session.client_salt,
        &encrypted_privkey,
        &master_key,
        &session.user_id,
    )
    .unwrap_or_else(|e| {
        eprintln!("error: {}", e);
        std::process::exit(1);
    });

    // Send to server
    eprintln!("Updating password...");
    let resp = vc.post_json_raw(
        "/auth/set-password",
        &serde_json::json!({
            "auth_key": change.new_auth_key_hex,
            "public_key": public_key,
            "encrypted_private_key": change.new_encrypted_private_key,
            "client_salt": change.new_client_salt,
            "current_auth_key": change.current_auth_key_hex,
            "encrypted_master_key": change.new_encrypted_master_key,
        }),
    );

    if !resp.status().is_success() {
        let text = resp.text().unwrap_or_default();
        eprintln!("error: password change failed: {}", text);
        std::process::exit(1);
    }

    let auth_resp: serde_json::Value = resp.json().unwrap_or_default();
    let new_jwt = auth_resp["token"]
        .as_str()
        .unwrap_or(&session.jwt)
        .to_string();

    // Update session with new salt and JWT
    save_session(&Session {
        api_url: session.api_url.clone(),
        jwt: new_jwt,
        email: session.email.clone(),
        user_id: session.user_id.clone(),
        client_salt: change.new_client_salt,
    });

    // Clear agent cache (force re-auth with new password)
    crate::agent::run_lock();

    eprintln!("Password changed successfully.");
}

pub fn run_logout() {
    clear_session();
    eprintln!("Logged out.");
}

pub fn run_status(api_url: &str) {
    if std::env::var("VAULT_API_KEY").is_ok() {
        eprintln!("Auth: VAULT_API_KEY environment variable set");
    } else {
        match load_session() {
            Some(session) => {
                eprintln!("Auth: session ({})", session.email);
                eprintln!("API:  {}", session.api_url);
            }
            None => {
                eprintln!("Auth: not logged in");
                eprintln!("API:  {}", api_url);
            }
        }
    }
    crate::agent::run_status();
}
