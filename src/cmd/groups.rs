use super::*;

pub fn run_group(client: &reqwest::blocking::Client, api_url: &str, action: crate::GroupAction) {
    match action {
        crate::GroupAction::Create { name } => run_create(client, api_url, &name),
        crate::GroupAction::List { json } => run_list(client, api_url, json),
        crate::GroupAction::Show { group, json } => run_show(client, api_url, &group, json),
        crate::GroupAction::Rename { group, new_name } => {
            run_rename(client, api_url, &group, &new_name)
        }
        crate::GroupAction::Delete { group } => run_delete(client, api_url, &group),
        crate::GroupAction::Add { group, label } => run_add(client, api_url, &group, &label),
        crate::GroupAction::Remove { group, label } => run_remove(client, api_url, &group, &label),
        crate::GroupAction::Items { group, json } => run_items(client, api_url, &group, json),
    }
}

fn encrypt_group_blob(
    master_key: &MasterKey,
    user_id: &str,
    name: &str,
) -> (String, Vec<u8>, Vec<u8>) {
    let (blob_b64, wrapped_key, nonce) =
        vault_core::client::encrypt_group(master_key, user_id, name).unwrap_or_else(|e| {
            eprintln!("error encrypting group: {}", e);
            std::process::exit(1);
        });
    (blob_b64, wrapped_key, nonce.to_vec())
}

fn decrypt_group_name_from_json(
    group: &serde_json::Value,
    master_key: &MasterKey,
    user_id: &str,
) -> Option<String> {
    let wrapped_key = json_to_bytes(&group["wrapped_key"]);
    let nonce = json_to_bytes(&group["nonce"]);
    if wrapped_key.is_empty() || nonce.is_empty() {
        return None;
    }
    let blob_b64 = group["encrypted_blob"].as_str()?;

    vault_core::client::decrypt_group_name(master_key, user_id, &wrapped_key, &nonce, blob_b64).ok()
}

fn fetch_groups_decrypted(
    vc: &VaultClient,
    master_key: &MasterKey,
    user_id: &str,
) -> Vec<(String, String, serde_json::Value)> {
    let groups: Vec<serde_json::Value> = vc.get("/groups").json().expect("invalid JSON");
    let mut result = Vec::new();
    for group in groups {
        let id = group["id"].as_str().unwrap_or("").to_string();
        if let Some(name) = decrypt_group_name_from_json(&group, master_key, user_id) {
            result.push((id, name, group));
        }
    }
    result
}

fn resolve_group_id(
    vc: &VaultClient,
    master_key: &MasterKey,
    user_id: &str,
    name_or_id: &str,
) -> String {
    // Try as UUID first
    if uuid::Uuid::parse_str(name_or_id).is_ok() {
        return name_or_id.to_string();
    }

    let groups = fetch_groups_decrypted(vc, master_key, user_id);
    groups
        .iter()
        .find(|(_, name, _)| name == name_or_id)
        .map(|(id, _, _)| id.clone())
        .unwrap_or_else(|| {
            eprintln!("error: group '{}' not found", name_or_id);
            std::process::exit(1);
        })
}

fn run_create(client: &reqwest::blocking::Client, api_url: &str, name: &str) {
    let auth = get_auth(client, api_url);
    let master_key = match &auth {
        AuthContext::Full { master_key, .. } => master_key,
        AuthContext::Scoped { .. } => {
            eprintln!("error: scoped API keys cannot create groups");
            std::process::exit(1);
        }
    };

    let user_id = load_session().map(|s| s.user_id).unwrap_or_default();

    let (blob_b64, wrapped_key, nonce) = encrypt_group_blob(master_key, &user_id, name);

    let vc = VaultClient::from_auth(&auth);
    let body: serde_json::Value = vc
        .post_json(
            "/groups",
            &serde_json::json!({
                "encrypted_blob": blob_b64,
                "wrapped_key": wrapped_key,
                "nonce": nonce,
            }),
        )
        .json()
        .unwrap_or_default();
    let id = body["id"].as_str().unwrap_or("?");
    eprintln!("Group '{}' created (ID: {}).", name, id);
}

fn run_list(client: &reqwest::blocking::Client, api_url: &str, json: bool) {
    let auth = get_auth(client, api_url);
    let master_key = match &auth {
        AuthContext::Full { master_key, .. } => master_key,
        AuthContext::Scoped { .. } => {
            eprintln!("error: scoped API keys cannot list groups");
            std::process::exit(1);
        }
    };

    let user_id = load_session().map(|s| s.user_id).unwrap_or_default();

    let vc = VaultClient::from_auth(&auth);
    let groups = fetch_groups_decrypted(&vc, master_key, &user_id);

    if json {
        let out: Vec<_> = groups
            .iter()
            .map(|(id, name, _)| serde_json::json!({"id": id, "name": name}))
            .collect();
        println!("{}", serde_json::to_string_pretty(&out).expect("serialize"));
        return;
    }

    if groups.is_empty() {
        eprintln!("No groups found.");
        return;
    }

    println!("{:<38} NAME", "ID");
    println!("{}", "-".repeat(60));
    for (id, name, _) in &groups {
        println!("{:<38} {}", id, name);
    }
}

fn run_show(client: &reqwest::blocking::Client, api_url: &str, group: &str, json: bool) {
    let auth = get_auth(client, api_url);
    let master_key = match &auth {
        AuthContext::Full { master_key, .. } => master_key,
        AuthContext::Scoped { .. } => {
            eprintln!("error: scoped API keys cannot view groups");
            std::process::exit(1);
        }
    };

    let user_id = load_session().map(|s| s.user_id).unwrap_or_default();
    let vc = VaultClient::from_auth(&auth);
    let group_id = resolve_group_id(&vc, master_key, &user_id, group);

    // Fetch items in this group
    run_items_by_id(
        client,
        auth.api_url(),
        auth.jwt(),
        master_key,
        &user_id,
        &group_id,
        json,
    );
}

fn run_rename(client: &reqwest::blocking::Client, api_url: &str, group: &str, new_name: &str) {
    let auth = get_auth(client, api_url);
    let master_key = match &auth {
        AuthContext::Full { master_key, .. } => master_key,
        AuthContext::Scoped { .. } => {
            eprintln!("error: scoped API keys cannot update groups");
            std::process::exit(1);
        }
    };

    let user_id = load_session().map(|s| s.user_id).unwrap_or_default();
    let vc = VaultClient::from_auth(&auth);
    let group_id = resolve_group_id(&vc, master_key, &user_id, group);

    let (blob_b64, wrapped_key, nonce) = encrypt_group_blob(master_key, &user_id, new_name);

    vc.put_json(
        &format!("/groups/{}", group_id),
        &serde_json::json!({
            "encrypted_blob": blob_b64,
            "wrapped_key": wrapped_key,
            "nonce": nonce,
        }),
    );

    eprintln!("Group renamed to '{}'.", new_name);
}

fn run_delete(client: &reqwest::blocking::Client, api_url: &str, group: &str) {
    let auth = get_auth(client, api_url);
    let master_key = match &auth {
        AuthContext::Full { master_key, .. } => master_key,
        AuthContext::Scoped { .. } => {
            eprintln!("error: scoped API keys cannot delete groups");
            std::process::exit(1);
        }
    };

    let user_id = load_session().map(|s| s.user_id).unwrap_or_default();
    let vc = VaultClient::from_auth(&auth);
    let group_id = resolve_group_id(&vc, master_key, &user_id, group);

    vc.delete(&format!("/groups/{}", group_id));
    eprintln!("Group deleted.");
}

fn run_add(client: &reqwest::blocking::Client, api_url: &str, group: &str, label: &str) {
    let auth = get_auth(client, api_url);
    let master_key = match &auth {
        AuthContext::Full { master_key, .. } => master_key,
        AuthContext::Scoped { .. } => {
            eprintln!("error: scoped API keys cannot modify groups");
            std::process::exit(1);
        }
    };

    let user_id = load_session().map(|s| s.user_id).unwrap_or_default();
    let vc = VaultClient::from_auth(&auth);
    let group_id = resolve_group_id(&vc, master_key, &user_id, group);

    // Resolve item by label
    let secrets = fetch_and_decrypt_secrets(client, &auth);
    let (item_id, _, _) = secrets
        .iter()
        .find(|(_, blob, _)| blob.display_name() == label)
        .unwrap_or_else(|| {
            eprintln!("error: item '{}' not found", label);
            std::process::exit(1);
        });

    vc.post_json(
        &format!("/groups/{}/items", group_id),
        &serde_json::json!({ "item_id": item_id }),
    );

    eprintln!("Item '{}' added to group.", label);
}

fn run_remove(client: &reqwest::blocking::Client, api_url: &str, group: &str, label: &str) {
    let auth = get_auth(client, api_url);
    let master_key = match &auth {
        AuthContext::Full { master_key, .. } => master_key,
        AuthContext::Scoped { .. } => {
            eprintln!("error: scoped API keys cannot modify groups");
            std::process::exit(1);
        }
    };

    let user_id = load_session().map(|s| s.user_id).unwrap_or_default();
    let vc = VaultClient::from_auth(&auth);
    let group_id = resolve_group_id(&vc, master_key, &user_id, group);

    // Resolve item by label
    let secrets = fetch_and_decrypt_secrets(client, &auth);
    let (item_id, _, _) = secrets
        .iter()
        .find(|(_, blob, _)| blob.display_name() == label)
        .unwrap_or_else(|| {
            eprintln!("error: item '{}' not found", label);
            std::process::exit(1);
        });

    vc.delete(&format!("/groups/{}/items/{}", group_id, item_id));
    eprintln!("Item '{}' removed from group.", label);
}

fn run_items(client: &reqwest::blocking::Client, api_url: &str, group: &str, json: bool) {
    let auth = get_auth(client, api_url);
    let master_key = match &auth {
        AuthContext::Full { master_key, .. } => master_key,
        AuthContext::Scoped { .. } => {
            eprintln!("error: scoped API keys cannot view groups");
            std::process::exit(1);
        }
    };

    let user_id = load_session().map(|s| s.user_id).unwrap_or_default();
    let vc = VaultClient::from_auth(&auth);
    let group_id = resolve_group_id(&vc, master_key, &user_id, group);

    run_items_by_id(
        client,
        auth.api_url(),
        auth.jwt(),
        master_key,
        &user_id,
        &group_id,
        json,
    );
}

fn run_items_by_id(
    client: &reqwest::blocking::Client,
    api_url: &str,
    jwt: &str,
    master_key: &MasterKey,
    user_id: &str,
    group_id: &str,
    json: bool,
) {
    let vc = VaultClient::new(api_url, jwt);
    let items: Vec<serde_json::Value> = vc
        .get(&format!("/groups/{}/items", group_id))
        .json()
        .expect("invalid JSON");

    let enc_key = derive_subkey(master_key, b"vault-enc").unwrap_or_else(|e| {
        eprintln!("error: {}", e);
        std::process::exit(1);
    });

    let wrap_aad = if user_id.is_empty() {
        Vec::new()
    } else {
        format!("wrap:{}", user_id).into_bytes()
    };

    let mut decrypted_items = Vec::new();
    for item in &items {
        let item_id = item["id"].as_str().unwrap_or("").to_string();
        let wrapped_key = json_to_bytes(&item["wrapped_key"]);
        let nonce = json_to_bytes(&item["nonce"]);
        if wrapped_key.is_empty() || nonce.is_empty() {
            continue;
        }

        let item_key_plain = match vault_core::crypto::decrypt_item_auto(
            &enc_key,
            &wrapped_key,
            &nonce,
            &wrap_aad,
        ) {
            Ok(k) => k,
            Err(_) => continue,
        };
        if item_key_plain.len() != 32 {
            continue;
        }
        let mut item_key = [0u8; 32];
        item_key.copy_from_slice(&item_key_plain);

        let has_file_blob = item["file_blob_key"]
            .as_str()
            .is_some_and(|s| !s.is_empty());
        let blob_opt = if has_file_blob {
            decrypt_inline_envelope(
                item["encrypted_blob"].as_str().unwrap_or(""),
                &item_key,
                user_id,
            )
        } else {
            decrypt_item_blob(client, api_url, jwt, &item_id, &item_key, user_id)
        };

        if let Some(blob) = blob_opt {
            decrypted_items.push((item_id, blob));
        }
    }

    if json {
        let out: Vec<_> = decrypted_items
            .iter()
            .map(|(id, blob)| {
                serde_json::json!({
                    "id": id,
                    "name": blob.display_name(),
                    "type": if blob.is_file() { "file" } else { "secret" },
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&out).expect("serialize"));
        return;
    }

    if decrypted_items.is_empty() {
        eprintln!("No items in group.");
        return;
    }

    for (_, blob) in &decrypted_items {
        if blob.is_file() {
            println!("[file] {}", blob.display_name());
        } else {
            println!("{}", blob.display_name());
        }
    }
}
