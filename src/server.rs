use axum::{
    extract::{Extension, Json, Path, Query, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Router,
};
use rand::RngCore;
use serde_json::json;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

use vault_core::auth::{self, Claims};
use vault_core::hashing;
use vault_core::requests;

use crate::db::Database;

// --- Shared State ---

pub struct ServerState {
    pub db: Database,
    pub jwt_secret: String,
}

type AppState = Arc<ServerState>;

// --- Error wrapper ---

struct ApiError(vault_core::error::ApiError);

impl From<vault_core::error::ApiError> for ApiError {
    fn from(e: vault_core::error::ApiError) -> Self {
        Self(e)
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        Self(vault_core::error::ApiError::Internal(e.to_string()))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.0.status_code()).unwrap();
        let message = match &self.0 {
            vault_core::error::ApiError::Internal(_) => "internal server error".to_string(),
            other => other.to_string(),
        };
        let body = axum::Json(json!({ "error": message }));
        (status, body).into_response()
    }
}

// --- Auth Middleware ---

async fn auth_middleware(
    State(state): State<AppState>,
    mut req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let token = match auth_header {
        Some(t) => t,
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    let claims =
        auth::decode_jwt(token, &state.jwt_secret).map_err(|_| StatusCode::UNAUTHORIZED)?;

    if !claims.email_verified {
        return Err(StatusCode::FORBIDDEN);
    }

    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}

// --- Router ---

pub fn build_router(state: AppState) -> Router {
    let public = Router::new()
        .route("/health", get(health))
        .route("/config", get(config))
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/client-params", post(client_params))
        .route("/auth/api-key", post(auth_api_key))
        .route("/auth/refresh", post(refresh))
        .route("/users/public-key", get(get_public_key));

    let protected = Router::new()
        .route("/auth/me", get(me))
        .route("/items", post(create_item))
        .route("/items", get(list_items))
        .route("/items/{id}", get(get_item))
        .route("/items/{id}", delete(delete_item))
        .route("/items/{id}/blob", get(get_item_blob))
        .route("/items/upload-url", post(upload_url))
        .route("/items/upload/{*key}", put(upload_blob))
        .route("/grants", post(create_grant))
        .route("/grants", get(list_grants))
        .route("/grants/{id}", get(get_grant))
        .route("/grants/{id}/access", post(access_grant))
        .route("/grants/{id}", delete(revoke_grant))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    Router::new()
        .merge(public)
        .merge(protected)
        .with_state(state)
}

// --- Public Handlers ---

async fn health() -> Json<serde_json::Value> {
    Json(json!({"status": "ok"}))
}

async fn config() -> Json<serde_json::Value> {
    Json(json!({"dev_mode": true}))
}

async fn register(
    State(state): State<AppState>,
    Json(body): Json<requests::RegisterRequest>,
) -> Result<(StatusCode, Json<requests::AuthResponse>), ApiError> {
    if !body.email.contains('@') || body.email.len() < 3 {
        return Err(vault_core::error::ApiError::BadRequest("invalid email".into()).into());
    }
    if body.auth_key.len() < 32 {
        return Err(vault_core::error::ApiError::BadRequest("auth_key too short".into()).into());
    }

    let hash = hashing::hash_auth_key(&body.auth_key)
        .map_err(|e| vault_core::error::ApiError::Internal(format!("hashing failed: {e}")))?;

    let user_id = Uuid::new_v4().to_string();

    match state.db.create_user(
        &user_id,
        &body.email,
        &hash,
        &body.public_key,
        &body.encrypted_private_key,
        body.encrypted_master_key.as_deref(),
        &body.client_salt,
    ) {
        Ok(_) => {}
        Err(e) if e.to_string().contains("UNIQUE") => {
            return Err(
                vault_core::error::ApiError::Conflict("email already registered".into()).into(),
            );
        }
        Err(e) => return Err(e.into()),
    }

    let uid = Uuid::parse_str(&user_id).unwrap();
    let token = auth::encode_jwt(uid, &body.email, true, &state.jwt_secret)
        .map_err(|e| vault_core::error::ApiError::Internal(e.to_string()))?;

    state
        .db
        .audit_log(&user_id, "register", "user", Some(&user_id), &json!({}));

    Ok((
        StatusCode::CREATED,
        Json(requests::AuthResponse { token, user_id }),
    ))
}

async fn login(
    State(state): State<AppState>,
    Json(body): Json<requests::LoginRequest>,
) -> Result<Json<requests::AuthResponse>, ApiError> {
    let user = state
        .db
        .get_user_by_email(&body.email)?
        .ok_or(vault_core::error::ApiError::Unauthorized)?;

    let valid = hashing::verify_auth_key(&body.auth_key, &user.auth_key_hash)
        .map_err(|e| vault_core::error::ApiError::Internal(format!("verify failed: {e}")))?;

    if !valid {
        return Err(vault_core::error::ApiError::Unauthorized.into());
    }

    let uid = Uuid::parse_str(&user.id).unwrap();
    let token = auth::encode_jwt(uid, &user.email, true, &state.jwt_secret)
        .map_err(|e| vault_core::error::ApiError::Internal(e.to_string()))?;

    state
        .db
        .audit_log(&user.id, "login", "user", Some(&user.id), &json!({}));

    Ok(Json(requests::AuthResponse {
        token,
        user_id: user.id,
    }))
}

async fn client_params(
    State(state): State<AppState>,
    Json(body): Json<requests::LookupRequest>,
) -> Json<serde_json::Value> {
    match state.db.get_user_by_email(&body.email) {
        Ok(Some(user)) => Json(json!({
            "client_salt": user.client_salt,
            "has_recovery": false,
        })),
        _ => {
            // Return dummy salt to prevent enumeration
            let mut dummy_salt = vec![0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut dummy_salt);
            Json(json!({
                "client_salt": dummy_salt,
                "has_recovery": false,
            }))
        }
    }
}

async fn auth_api_key(
    State(state): State<AppState>,
    Json(body): Json<requests::ApiKeyAuthRequest>,
) -> Result<Json<requests::ApiKeyAuthResponse>, ApiError> {
    // Find API keys by prefix
    type ApiKeyRow = (
        String,
        String,
        String,
        Option<Vec<u8>>,
        Vec<u8>,
        Option<Vec<u8>>,
        String,
        Option<String>,
    );
    let keys: Vec<ApiKeyRow> = {
        let conn = state.db.conn_ref().lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, user_id, key_hash, wrapped_master_key, encrypted_private_key, public_key, scopes, expires_at
             FROM api_keys WHERE key_prefix = ?1",
        ).map_err(|e| vault_core::error::ApiError::Internal(e.to_string()))?;
        let result: Vec<ApiKeyRow> = stmt
            .query_map(rusqlite::params![body.key_prefix], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            })
            .map_err(|e| vault_core::error::ApiError::Internal(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect();
        result
    };

    // Try each matching key
    for (
        key_id,
        user_id,
        key_hash,
        wrapped_master_key,
        encrypted_private_key,
        public_key,
        scopes_str,
        expires_at,
    ) in &keys
    {
        // Check expiry
        if let Some(exp) = expires_at {
            if let Ok(exp_dt) = chrono::DateTime::parse_from_rfc3339(exp) {
                if exp_dt < chrono::Utc::now() {
                    continue;
                }
            }
        }

        let valid = hashing::verify_auth_key(&body.auth_key, key_hash).unwrap_or(false);
        if !valid {
            continue;
        }

        // Found a match
        let user =
            state
                .db
                .get_user_by_id(user_id)?
                .ok_or(vault_core::error::ApiError::Internal(
                    "user not found".into(),
                ))?;

        let scopes: serde_json::Value = serde_json::from_str(scopes_str).unwrap_or_default();
        let read_only = scopes
            .get("read_only")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let uid = Uuid::parse_str(user_id).unwrap();
        let ak_id = Uuid::parse_str(key_id).unwrap();
        let token = auth::encode_jwt_api_key(uid, &user.email, ak_id, read_only, &state.jwt_secret)
            .map_err(|e| vault_core::error::ApiError::Internal(e.to_string()))?;

        return Ok(Json(requests::ApiKeyAuthResponse {
            token,
            user_id: user_id.clone(),
            api_key_id: key_id.clone(),
            wrapped_master_key: wrapped_master_key.clone(),
            encrypted_private_key: encrypted_private_key.clone(),
            public_key: public_key.clone(),
        }));
    }

    Err(vault_core::error::ApiError::Unauthorized.into())
}

async fn refresh(
    State(state): State<AppState>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<Json<requests::AuthResponse>, ApiError> {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(vault_core::error::ApiError::Unauthorized)?;

    let claims = auth::decode_jwt_allow_expired(auth_header, &state.jwt_secret)
        .map_err(|_| vault_core::error::ApiError::Unauthorized)?;

    // Reject if expired more than 1 hour ago
    let now = chrono::Utc::now().timestamp() as usize;
    if claims.exp < now && now - claims.exp > 3600 {
        return Err(vault_core::error::ApiError::Unauthorized.into());
    }

    let token = auth::encode_jwt(
        claims.sub,
        &claims.email,
        claims.email_verified,
        &state.jwt_secret,
    )
    .map_err(|e| vault_core::error::ApiError::Internal(e.to_string()))?;

    Ok(Json(requests::AuthResponse {
        token,
        user_id: claims.sub.to_string(),
    }))
}

async fn get_public_key(
    State(state): State<AppState>,
    Query(query): Query<requests::PublicKeyQuery>,
) -> Result<Json<requests::PublicKeyResponse>, ApiError> {
    let user = state
        .db
        .get_user_by_email(&query.email)?
        .ok_or(vault_core::error::ApiError::NotFound)?;

    Ok(Json(requests::PublicKeyResponse {
        public_key: user.public_key,
    }))
}

// --- Protected Handlers ---

async fn me(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = state
        .db
        .get_user_by_id(&claims.sub.to_string())?
        .ok_or(vault_core::error::ApiError::NotFound)?;

    Ok(Json(json!({
        "user_id": user.id,
        "email": user.email,
        "email_verified": true,
        "public_key": user.public_key,
        "encrypted_private_key": user.encrypted_private_key,
        "client_salt": user.client_salt,
        "encrypted_master_key": user.encrypted_master_key,
        "has_recovery": false,
        "created_at": user.created_at,
    })))
}

// --- Items ---

async fn create_item(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(body): Json<requests::CreateItemRequest>,
) -> Result<(StatusCode, Json<crate::db::ItemRow>), ApiError> {
    auth::check_write_allowed(&claims)?;

    if body.item_type != "encrypted" {
        return Err(vault_core::error::ApiError::BadRequest(
            "item_type must be 'encrypted'".into(),
        )
        .into());
    }
    if let Some(ref meta) = body.metadata {
        if meta.as_object().is_some_and(|m| !m.is_empty()) {
            return Err(
                vault_core::error::ApiError::BadRequest("metadata must be empty".into()).into(),
            );
        }
    }

    let item_id = Uuid::new_v4().to_string();
    let encrypted_blob = body.encrypted_blob.unwrap_or_default();
    let metadata = body.metadata.unwrap_or(json!({}));

    let item = state.db.create_item(
        &item_id,
        &claims.sub.to_string(),
        &encrypted_blob,
        &body.wrapped_key,
        &body.nonce,
        &body.item_type,
        body.classification.as_str(),
        &metadata,
        body.size_bytes,
        body.file_blob_key.as_deref(),
    )?;

    state.db.audit_log(
        &claims.sub.to_string(),
        "create",
        "item",
        Some(&item_id),
        &json!({}),
    );

    Ok((StatusCode::CREATED, Json(item)))
}

async fn list_items(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<crate::db::ItemRow>>, ApiError> {
    let items = state.db.list_items(&claims.sub.to_string())?;
    Ok(Json(items))
}

async fn get_item(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<Json<crate::db::ItemRow>, ApiError> {
    let item = state
        .db
        .get_item(&id, &claims.sub.to_string())?
        .ok_or(vault_core::error::ApiError::NotFound)?;
    Ok(Json(item))
}

async fn delete_item(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    auth::check_write_allowed(&claims)?;

    let deleted = state.db.delete_item(&id, &claims.sub.to_string())?;
    if !deleted {
        return Err(vault_core::error::ApiError::NotFound.into());
    }

    state.db.audit_log(
        &claims.sub.to_string(),
        "delete",
        "item",
        Some(&id),
        &json!({}),
    );

    Ok(StatusCode::NO_CONTENT)
}

async fn get_item_blob(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let item = state
        .db
        .get_item(&id, &claims.sub.to_string())?
        .ok_or(vault_core::error::ApiError::NotFound)?;

    if let Some(blob_key) = &item.file_blob_key {
        let data = state
            .db
            .read_blob(blob_key)
            .map_err(|e| vault_core::error::ApiError::Internal(format!("blob read failed: {e}")))?;
        Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream")],
            data,
        )
            .into_response())
    } else {
        // Inline blob
        Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream")],
            item.encrypted_blob.into_bytes(),
        )
            .into_response())
    }
}

async fn upload_url(
    State(_state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let blob_key = format!("items/{}/{}", claims.sub, Uuid::new_v4());
    // For local server, return a proxy upload URL
    Ok(Json(json!({
        "upload_url": format!("/items/upload/{}", blob_key),
        "s3_key": blob_key,
        "proxy_upload": true,
    })))
}

async fn upload_blob(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(key): Path<String>,
    body: axum::body::Bytes,
) -> Result<StatusCode, ApiError> {
    // Validate key belongs to this user
    let expected_prefix = format!("items/{}/", claims.sub);
    if !key.starts_with(&expected_prefix) {
        return Err(vault_core::error::ApiError::Forbidden.into());
    }

    state
        .db
        .write_blob(&key, &body)
        .map_err(|e| vault_core::error::ApiError::Internal(format!("blob write failed: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

// --- Grants ---

async fn create_grant(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(body): Json<requests::CreateGrantRequest>,
) -> Result<(StatusCode, Json<crate::db::GrantRow>), ApiError> {
    auth::check_write_allowed(&claims)?;

    let item_id = body.item_id.map(|id| id.to_string());

    // Verify grantor owns the item
    if let Some(ref iid) = item_id {
        state
            .db
            .get_item(iid, &claims.sub.to_string())?
            .ok_or(vault_core::error::ApiError::NotFound)?;
    }

    // Resolve grantee
    let grantee_id = state
        .db
        .get_user_by_email(&body.grantee_email)?
        .map(|u| u.id);

    let grant_id = Uuid::new_v4().to_string();
    let grant = state.db.create_grant(
        &grant_id,
        item_id.as_deref(),
        &claims.sub.to_string(),
        &body.grantee_email,
        grantee_id.as_deref(),
        &body.wrapped_key,
        &body.ephemeral_pubkey,
        &body.policy,
        body.file_wrapped_key.as_deref(),
    )?;

    state.db.audit_log(
        &claims.sub.to_string(),
        "create",
        "grant",
        Some(&grant_id),
        &json!({}),
    );

    Ok((StatusCode::CREATED, Json(grant)))
}

async fn list_grants(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<crate::db::GrantRow>>, ApiError> {
    let grants = state
        .db
        .list_grants_for_user(&claims.sub.to_string(), &claims.email)?;
    Ok(Json(grants))
}

async fn get_grant(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<Json<crate::db::GrantRow>, ApiError> {
    let grant = state
        .db
        .get_grant(&id)?
        .ok_or(vault_core::error::ApiError::NotFound)?;

    let uid = claims.sub.to_string();
    if grant.grantor_id != uid
        && grant.grantee_id.as_deref() != Some(&uid)
        && grant.grantee_email != claims.email
    {
        return Err(vault_core::error::ApiError::NotFound.into());
    }

    Ok(Json(grant))
}

async fn access_grant(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    body: Option<Json<requests::AccessGrantRequest>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let grant = state
        .db
        .get_grant(&id)?
        .ok_or(vault_core::error::ApiError::NotFound)?;

    let uid = claims.sub.to_string();

    // Verify grantee
    if grant.grantee_id.as_deref() != Some(&uid) && grant.grantee_email != claims.email {
        return Err(vault_core::error::ApiError::NotFound.into());
    }

    if grant.status == "revoked" {
        return Err(vault_core::error::ApiError::NotFound.into());
    }

    // Policy checks
    let policy: vault_core::Policy =
        serde_json::from_value(grant.policy.clone()).unwrap_or_default();
    let operation = body.map(|b| b.0.operation).unwrap_or_else(|| "view".into());
    let now = chrono::Utc::now();

    // Parse claimed_at for TTL calculation
    let first_accessed_at = grant
        .claimed_at
        .as_ref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));

    if policy.is_expired(now, grant.view_count, first_accessed_at) {
        return Err(vault_core::error::ApiError::Forbidden.into());
    }
    if !policy.is_access_allowed(now, grant.view_count, first_accessed_at, &operation, None) {
        return Err(vault_core::error::ApiError::Forbidden.into());
    }

    // Claim on first access
    if grant.status == "pending" {
        state.db.claim_grant(&id, &uid)?;
    }

    let new_count = state
        .db
        .increment_view_count(&id, policy.max_views)?
        .ok_or(vault_core::error::ApiError::Forbidden)?;

    // Get the item blob
    let item_id = grant
        .item_id
        .as_ref()
        .ok_or(vault_core::error::ApiError::NotFound)?;
    let item = state
        .db
        .get_item_any_owner(item_id)?
        .ok_or(vault_core::error::ApiError::NotFound)?;

    state.db.audit_log(
        &uid,
        "access",
        "grant",
        Some(&id),
        &json!({"operation": operation}),
    );

    Ok(Json(json!({
        "id": grant.id,
        "item_id": grant.item_id,
        "grantor_id": grant.grantor_id,
        "grantee_email": grant.grantee_email,
        "grantee_id": uid,
        "wrapped_key": grant.wrapped_key,
        "ephemeral_pubkey": grant.ephemeral_pubkey,
        "policy": grant.policy,
        "status": "active",
        "view_count": new_count,
        "created_at": grant.created_at,
        "claimed_at": grant.claimed_at,
        "revoked_at": grant.revoked_at,
        "file_wrapped_key": grant.file_wrapped_key,
        "encrypted_blob": item.encrypted_blob,
        "nonce": item.nonce,
    })))
}

async fn revoke_grant(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    auth::check_write_allowed(&claims)?;

    let revoked = state.db.revoke_grant(&id, &claims.sub.to_string())?;
    if !revoked {
        return Err(vault_core::error::ApiError::NotFound.into());
    }

    state.db.audit_log(
        &claims.sub.to_string(),
        "revoke",
        "grant",
        Some(&id),
        &json!({}),
    );

    Ok(StatusCode::NO_CONTENT)
}

// --- Server startup ---

pub fn default_db_path() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("blindkeep")
        .join("vault.db")
}

pub async fn run_server(host: &str, port: u16, db_path: PathBuf) {
    let db = Database::open(&db_path).unwrap_or_else(|e| {
        eprintln!("error opening database: {e}");
        std::process::exit(1);
    });

    // Get or create JWT signing key
    let jwt_secret = match db.get_config("jwt_signing_key") {
        Some(key) => hex::encode(key),
        None => {
            let mut key = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut key);
            db.set_config("jwt_signing_key", &key);
            hex::encode(key)
        }
    };

    let state = Arc::new(ServerState { db, jwt_secret });
    let app = build_router(state);

    let addr: SocketAddr = format!("{host}:{port}").parse().unwrap_or_else(|e| {
        eprintln!("error: invalid listen address: {e}");
        std::process::exit(1);
    });

    eprintln!("BlindKeep local server listening on http://{addr}");
    eprintln!("Database: {}", db_path.display());

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| {
            eprintln!("error: failed to bind {addr}: {e}");
            std::process::exit(1);
        });

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .unwrap_or_else(|e| {
        eprintln!("error: server failed: {e}");
        std::process::exit(1);
    });

    eprintln!("Server stopped.");
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl+c");
    eprintln!("\nShutting down...");
}
