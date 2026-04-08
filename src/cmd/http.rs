use reqwest::blocking::{Client, Response};

/// Lightweight HTTP client that wraps reqwest with bearer auth and error handling.
pub struct VaultClient {
    client: Client,
    base_url: String,
    token: String,
}

impl VaultClient {
    pub fn new(base_url: &str, token: &str) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.to_string(),
            token: token.to_string(),
        }
    }

    /// Build a `VaultClient` from an [`AuthContext`].
    pub fn from_auth(auth: &super::common::AuthContext) -> Self {
        Self::new(auth.api_url(), auth.jwt())
    }

    /// Build a `VaultClient` from a saved [`Session`].
    #[allow(dead_code)]
    pub fn from_session(session: &super::common::Session) -> Self {
        Self::new(&session.api_url, &session.jwt)
    }

    /// Return a reference to the inner reqwest client (e.g. for presigned S3 uploads).
    pub fn inner(&self) -> &Client {
        &self.client
    }

    #[allow(dead_code)]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    #[allow(dead_code)]
    pub fn token(&self) -> &str {
        &self.token
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    // --- Checked methods (exit on non-2xx) ---

    pub fn get(&self, path: &str) -> Response {
        let resp = self
            .client
            .get(self.url(path))
            .bearer_auth(&self.token)
            .send()
            .unwrap_or_else(|e| fatal(&e));
        check(resp)
    }

    pub fn get_query<T: serde::Serialize>(&self, path: &str, query: &T) -> Response {
        let resp = self
            .client
            .get(self.url(path))
            .bearer_auth(&self.token)
            .query(query)
            .send()
            .unwrap_or_else(|e| fatal(&e));
        check(resp)
    }

    pub fn post_json<T: serde::Serialize>(&self, path: &str, body: &T) -> Response {
        let resp = self
            .client
            .post(self.url(path))
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .unwrap_or_else(|e| fatal(&e));
        check(resp)
    }

    pub fn put_json<T: serde::Serialize>(&self, path: &str, body: &T) -> Response {
        let resp = self
            .client
            .put(self.url(path))
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .unwrap_or_else(|e| fatal(&e));
        check(resp)
    }

    pub fn put_bytes(&self, path: &str, body: Vec<u8>) -> Response {
        let resp = self
            .client
            .put(self.url(path))
            .bearer_auth(&self.token)
            .body(body)
            .send()
            .unwrap_or_else(|e| fatal(&e));
        check(resp)
    }

    pub fn delete(&self, path: &str) -> Response {
        let resp = self
            .client
            .delete(self.url(path))
            .bearer_auth(&self.token)
            .send()
            .unwrap_or_else(|e| fatal(&e));
        check(resp)
    }

    // --- Raw methods (return response without status check) ---

    pub fn get_raw(&self, path: &str) -> Response {
        self.client
            .get(self.url(path))
            .bearer_auth(&self.token)
            .send()
            .unwrap_or_else(|e| fatal(&e))
    }

    pub fn get_query_raw<T: serde::Serialize>(&self, path: &str, query: &T) -> Response {
        self.client
            .get(self.url(path))
            .bearer_auth(&self.token)
            .query(query)
            .send()
            .unwrap_or_else(|e| fatal(&e))
    }

    pub fn post_json_raw<T: serde::Serialize>(&self, path: &str, body: &T) -> Response {
        self.client
            .post(self.url(path))
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .unwrap_or_else(|e| fatal(&e))
    }

    pub fn delete_raw(&self, path: &str) -> Response {
        self.client
            .delete(self.url(path))
            .bearer_auth(&self.token)
            .send()
            .unwrap_or_else(|e| fatal(&e))
    }

    // --- Unauthenticated methods (no bearer token) ---

    pub fn get_unauth(&self, path: &str) -> Response {
        let resp = self
            .client
            .get(self.url(path))
            .send()
            .unwrap_or_else(|e| fatal(&e));
        check(resp)
    }

    pub fn get_unauth_raw(&self, path: &str) -> Response {
        self.client
            .get(self.url(path))
            .send()
            .unwrap_or_else(|e| fatal(&e))
    }

    pub fn post_json_unauth<T: serde::Serialize>(&self, path: &str, body: &T) -> Response {
        let resp = self
            .client
            .post(self.url(path))
            .json(body)
            .send()
            .unwrap_or_else(|e| fatal(&e));
        check(resp)
    }

    pub fn post_json_unauth_raw<T: serde::Serialize>(&self, path: &str, body: &T) -> Response {
        self.client
            .post(self.url(path))
            .json(body)
            .send()
            .unwrap_or_else(|e| fatal(&e))
    }
}

fn fatal(e: &dyn std::fmt::Display) -> ! {
    eprintln!("error: {}", e);
    std::process::exit(1);
}

fn check(resp: Response) -> Response {
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().unwrap_or_default();
        eprintln!("error ({}): {}", status, text);
        std::process::exit(1);
    }
    resp
}
