// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Func
// SPDX-License-Identifier: Apache-2.0

//! # func-client
//!
//! Rust HTTP client for the Func standalone WASM execution service.

#![deny(missing_docs)]

use std::sync::Arc;

use sentin8_middleware::http_client::Sentin8HttpClient;
use thiserror::Error;

/// Errors returned by the Func client.
#[derive(Debug, Error)]
pub enum FuncError {
    /// The HTTP request failed or returned a non-success status.
    #[error("Func HTTP error: {0}")]
    Http(String),
    /// The response body could not be decoded.
    #[error("Func decode error: {0}")]
    Decode(String),
}

/// The Func client. Cheap to clone (wraps an `Arc`).
///
/// Two authentication postures (auth DESIGN §4.3f): the certificate path
/// (`with_workload_identity` — the TLS handshake presents the workload's
/// Acme-issued pair; no bearer header exists on the wire) for
/// service-to-service callers, and the bearer path (`new` — a user or
/// delegated token) for interactive flows.
#[derive(Clone)]
pub struct FuncClient {
    base_url: String,
    /// `None` on the certificate path — the TLS handshake IS the
    /// authentication; no bearer header is attached.
    auth_token: Option<Arc<String>>,
    http: Sentin8HttpClient,
}

impl FuncClient {
    /// Construct a bearer-authenticated client (user/delegated token
    /// flows — the token rides the `Authorization` header).
    ///
    /// - `base_url`: Func server URL.
    /// - `auth_token`: bearer token (scope `sentin8:func:write`).
    pub fn new(base_url: impl Into<String>, auth_token: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            auth_token: Some(Arc::new(auth_token.into())),
            http: Sentin8HttpClient::new(),
        }
    }

    /// Construct a **certificate-presenting** client (auth DESIGN
    /// §4.3f): every call presents the workload's Acme-issued client
    /// certificate in the TLS handshake — Func's TLS layer authenticates
    /// it and the enroll-published registry map authorizes the scopes.
    /// No bearer token exists on this path.
    ///
    /// # Errors
    /// [`FuncError::Http`] when the mTLS transport cannot be built
    /// (missing files / unreadable key) — a missing certificate identity
    /// is a provisioning state, surfaced loud.
    pub fn with_workload_identity(
        base_url: impl Into<String>,
        ca_cert_path: &str,
        cert_path: &str,
        key_path: &str,
    ) -> Result<Self, FuncError> {
        let mtls = sentin8_middleware::mtls::MtlsConfig::new(ca_cert_path, cert_path, key_path);
        let http = sentin8_middleware::mtls::build_mtls_client(&mtls)
            .map(Sentin8HttpClient::from_client)
            .map_err(|e| FuncError::Http(e.to_string()))?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            auth_token: None,
            http,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Attach the bearer header when the client carries a token (the
    /// certificate path attaches none — the TLS handshake is the
    /// authentication).
    fn with_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth_token {
            Some(t) => req.bearer_auth(t.as_str()),
            None => req,
        }
    }

    /// `POST /v1/modules` — upload a new WASM module.
    pub async fn upload(&self, req: &UploadRequest) -> Result<serde_json::Value, FuncError> {
        let resp = self
            .with_auth(self.http.post(self.url("/v1/modules")))
            .json(req)
            .send()
            .await
            .map_err(|e| FuncError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(FuncError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| FuncError::Decode(e.to_string()))
    }

    /// `GET /v1/modules` — list modules, optionally filtered.
    pub async fn list_modules(
        &self,
        domain: Option<&str>,
        product_id: Option<&str>,
    ) -> Result<Vec<serde_json::Value>, FuncError> {
        let mut url = self.url("/v1/modules");
        let mut sep = '?';
        if let Some(d) = domain {
            url.push_str(&format!("{sep}domain={d}"));
            sep = '&';
        }
        if let Some(p) = product_id {
            url.push_str(&format!("{sep}product_id={p}"));
        }
        let resp = self
            .with_auth(self.http.get(&url))
            .send()
            .await
            .map_err(|e| FuncError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(FuncError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| FuncError::Decode(e.to_string()))
    }

    /// `GET /v1/modules/{id}` — get module metadata.
    pub async fn get_module(&self, id: &str) -> Result<serde_json::Value, FuncError> {
        let resp = self
            .with_auth(self.http.get(self.url(&format!("/v1/modules/{id}"))))
            .send()
            .await
            .map_err(|e| FuncError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(FuncError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| FuncError::Decode(e.to_string()))
    }

    /// `POST /v1/modules/{id}/execute` — execute a hook.
    pub async fn execute(
        &self,
        id: &str,
        req: &ExecuteRequest,
    ) -> Result<serde_json::Value, FuncError> {
        let resp = self
            .with_auth(
                self.http
                    .post(self.url(&format!("/v1/modules/{id}/execute"))),
            )
            .json(req)
            .send()
            .await
            .map_err(|e| FuncError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(FuncError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| FuncError::Decode(e.to_string()))
    }

    /// `POST /v1/modules/{id}/validate` — dry-run validation.
    pub async fn validate(&self, id: &str) -> Result<serde_json::Value, FuncError> {
        let resp = self
            .with_auth(
                self.http
                    .post(self.url(&format!("/v1/modules/{id}/validate"))),
            )
            .send()
            .await
            .map_err(|e| FuncError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(FuncError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| FuncError::Decode(e.to_string()))
    }

    /// `POST /v1/modules/{id}/activate` — activate a module version.
    pub async fn activate(&self, id: &str) -> Result<(), FuncError> {
        let resp = self
            .with_auth(
                self.http
                    .post(self.url(&format!("/v1/modules/{id}/activate"))),
            )
            .send()
            .await
            .map_err(|e| FuncError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(FuncError::Http(format!("status {}", resp.status())));
        }
        Ok(())
    }

    /// `DELETE /v1/modules/{id}` — delete a module (draft or deprecated only).
    pub async fn delete(&self, id: &str) -> Result<(), FuncError> {
        let resp = self
            .with_auth(self.http.delete(self.url(&format!("/v1/modules/{id}"))))
            .send()
            .await
            .map_err(|e| FuncError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(FuncError::Http(format!("status {}", resp.status())));
        }
        Ok(())
    }
}

// ── Request/response types ──────────────────────────────────────────────

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A request to upload a new WASM module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadRequest {
    /// Owning business domain (e.g. `ledger`).
    pub domain: String,
    /// The product this module belongs to.
    pub product_id: String,
    /// Human-facing version label.
    pub version_label: String,
    /// Base64-encoded WASM binary.
    pub wasm_binary: String,
    /// Source language of the module (e.g. `rust`).
    pub wasm_language: String,
    /// Content hash of the binary, when supplied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wasm_hash: Option<String>,
    /// Hook names the module exports.
    pub hooks: Vec<String>,
    /// Module parameters schema/defaults.
    #[serde(default)]
    pub parameters: serde_json::Value,
    /// Optional human description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Proxy-back configuration: how Func-hosted functions reach the owning
/// service's internal API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackConfig {
    /// Base URL of the owning service.
    pub base_url: String,
    /// Bearer token used for proxy-back calls.
    pub auth_token: String,
    /// Internal path to POST for host function calls.
    pub internal_path: String,
    /// Import name → proxy-back path mapping.
    #[serde(default)]
    pub host_functions: HashMap<String, String>,
}

/// Request to execute a hook on a module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteRequest {
    /// The hook name to invoke.
    pub hook: String,
    /// Execution context (domain payload passed to the hook).
    pub context: serde_json::Value,
    /// Proxy-back configuration, when the module imports host functions.
    #[serde(default)]
    pub callback_config: Option<CallbackConfig>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn install_provider() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = sentin8_tls::crypto::sentin8_pq_provider().install_default();
        });
    }

    async fn serve(
        status_line: &'static str,
        body: &'static str,
    ) -> (tokio::task::JoinHandle<String>, std::net::SocketAddr) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let resp = format!(
                "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            req
        });
        (handle, addr)
    }

    #[tokio::test]
    async fn upload_posts_module_contract() {
        install_provider();
        let (handle, addr) = serve("HTTP/1.1 200 OK", r#"{"id":"m-1","version":1}"#).await;
        let c = FuncClient::new(format!("http://{addr}"), "tok");
        let req = UploadRequest {
            domain: "ledger".into(),
            product_id: "fraud-scan".into(),
            version_label: "v1".into(),
            wasm_binary: "AGFzbQ==".into(),
            wasm_language: "rust".into(),
            wasm_hash: Some("sha256:abcd".into()),
            hooks: vec!["on_posting".into()],
            parameters: serde_json::json!({}),
            description: None,
        };
        let out = c.upload(&req).await.unwrap();
        assert_eq!(out["id"], "m-1");
        let raw = handle.await.unwrap();
        assert!(raw.starts_with("POST /v1/modules HTTP/1.1"), "got: {raw}");
        assert!(raw.contains("\"product_id\":\"fraud-scan\""));
        assert!(raw.contains("\"wasm_hash\":\"sha256:abcd\""));
    }

    #[tokio::test]
    async fn execute_posts_hook_and_context() {
        install_provider();
        let (handle, addr) = serve("HTTP/1.1 200 OK", r#"{"ok":true}"#).await;
        let c = FuncClient::new(format!("http://{addr}"), "tok");
        let req = ExecuteRequest {
            hook: "on_posting".into(),
            context: serde_json::json!({"posting_id": "p-1", "amount": "10.00"}),
            callback_config: None,
        };
        c.execute("m-1", &req).await.unwrap();
        let raw = handle.await.unwrap();
        assert!(
            raw.starts_with("POST /v1/modules/m-1/execute HTTP/1.1"),
            "got: {raw}"
        );
        assert!(raw.contains("\"hook\":\"on_posting\""));
        assert!(raw.contains("\"posting_id\":\"p-1\""));
    }

    #[tokio::test]
    async fn list_modules_filters_build_query() {
        install_provider();
        let (handle, addr) = serve("HTTP/1.1 200 OK", "[]").await;
        let c = FuncClient::new(format!("http://{addr}"), "tok");
        c.list_modules(Some("ledger"), Some("fraud-scan"))
            .await
            .unwrap();
        let raw = handle.await.unwrap();
        assert!(
            raw.starts_with("GET /v1/modules?domain=ledger&product_id=fraud-scan HTTP/1.1"),
            "got: {raw}"
        );
    }

    #[tokio::test]
    async fn activate_and_delete_unit_return() {
        install_provider();
        for path in ["/v1/modules/m-1/activate", "/v1/modules/m-1"] {
            let (handle, addr) = serve("HTTP/1.1 200 OK", "").await;
            let c = FuncClient::new(format!("http://{addr}"), "tok");
            if path.ends_with("activate") {
                c.activate("m-1").await.unwrap();
            } else {
                c.delete("m-1").await.unwrap();
            }
            let raw = handle.await.unwrap();
            let expected = if path.ends_with("activate") {
                format!("POST {path} HTTP/1.1")
            } else {
                format!("DELETE {path} HTTP/1.1")
            };
            assert!(raw.starts_with(&expected), "got: {raw}");
        }
    }

    #[tokio::test]
    async fn validate_error_status_maps() {
        install_provider();
        let (handle, addr) = serve("HTTP/1.1 422 Unprocessable Entity", "{}").await;
        let c = FuncClient::new(format!("http://{addr}"), "tok");
        let err = c.validate("m-1").await.unwrap_err();
        assert!(
            matches!(err, FuncError::Http(ref m) if m.contains("422")),
            "{err:?}"
        );
        handle.await.unwrap();
    }
}
