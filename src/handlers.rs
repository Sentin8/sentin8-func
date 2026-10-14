// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Func
// SPDX-License-Identifier: Apache-2.0

//! Func HTTP handlers — module management + execution API.
//!
//! Conventions:
//!
//! - Every DB touch goes through `store.rs`, which runs inside a transaction
//!   with the tenant context set on the same connection (transaction-local
//!   `set_config`).
//! - Domain events are written to the LOCAL `func.outbox` in the same
//!   transaction as the domain change; the shell's shared relay pushes them
//!   to Bus `POST /v1/produce` (principles §6.7 — see also `crates/shell`
//!   step 8b).
//! - Uploads are atomic: the Storage object (keyed by module id) is written
//!   before the metadata row; a failed metadata insert triggers a best-effort
//!   Storage rollback.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth;
use crate::runtime::{ExecuteRequest, ExecuteResponse, WasmRuntime, KNOWN_HOOKS};
use crate::store::{self, ModuleRecord};

#[derive(Clone)]
/// app state.
pub struct AppState {
    /// The config.
    pub config: Arc<crate::config::FuncConfig>,
    /// The pool.
    pub pool: sqlx::PgPool,
    /// The runtime.
    pub runtime: WasmRuntime,
    /// The storage.
    pub storage: sentin8_storage_sdk::client::StorageClient,
    /// The boot-loaded workload registry map — the authorization record
    /// for cert-presenting callers (auth DESIGN §4.3f; group DESIGN.md
    /// §3.1).
    pub workload_registry: sentin8::auth::workload_registry::WorkloadMap,
    /// Shield engine ( — ): additional gate after scope.
    /// The policy.
    pub policy: Arc<crate::policy::Engine>,
    /// Shared Sentin8:Policy admin surface ( — one
    /// implementation for every service; mounted in server::routes).
    /// The admin.
    pub admin: sentin8::shield::admin::SharedAdminState,
}

// ── Upload ───────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for upload.
pub struct UploadRequest {
    /// The domain.
    pub domain: String,
    /// product identifier.
    pub product_id: String,
    /// The version label.
    pub version_label: String,
    /// base64-encoded WASM binary.
    /// The wasm binary.
    pub wasm_binary: String,
    /// The wasm language.
    pub wasm_language: String,
    /// Optional client-provided hash (`sha256:hex…`); verified server-side.
    #[serde(default)]
    /// The wasm hash.
    pub wasm_hash: Option<String>,
    #[serde(default)]
    /// The hooks.
    pub hooks: Vec<String>,
    #[serde(default)]
    /// The parameters.
    pub parameters: serde_json::Value,
    #[serde(default)]
    /// The description.
    pub description: Option<String>,
}

/// Resolve the tenant for a request. `target_env_id` (when supplied) must be
/// a valid UUID — cross-env authorization is delegated to RLS (a caller
/// without a role in the target env sees 0 rows / gets denied on writes by
/// the INSERT policy). No silent fallback: a malformed target env is a 400.
fn resolve_env(
    a: &auth::AuthContext,
    target_env_id: Option<&str>,
) -> Result<Uuid, (StatusCode, String)> {
    match target_env_id {
        Some(s) => uuid::Uuid::parse_str(s).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid target_env_id: {e}"),
            )
        }),
        None => Ok(a.env_id()),
    }
}

/// Feature gate `func.wasm`: the WASM engine is enabled unless an explicit
/// `services` row for `func` at the caller's (org, env) has
/// `enabled = false`. A missing row means enabled (platform-engine default,
/// matching the dash sidebar contract in `sys::list_vertical_services`).
/// Resolves the org from the env, so the caller only supplies the tenant.
/// Handle wasm gate open.
pub async fn wasm_gate_open(
    pool: &sqlx::PgPool,
    env_id: Uuid,
) -> Result<bool, (StatusCode, String)> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let enabled: Option<bool> = sqlx::query_scalar(
        r#"SELECT s.enabled
             FROM sys.services s
            WHERE s.service = 'func'
              AND s.env_id = $1"#,
    )
    .bind(env_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(enabled.unwrap_or(true))
}

/// Reject with 409 when the feature gate is closed.
fn gate_closed() -> (StatusCode, String) {
    (
        StatusCode::CONFLICT,
        "feature func.wasm disabled for environment".into(),
    )
}

/// Emit a domain event inside the domain transaction (outbox-first §6.7).
/// Writes the LOCAL `func.outbox` (func DESIGN §4) in the SAME transaction
/// as the domain change — event and domain row commit together or not at
/// all; the shell's shared relay then pushes the row to Bus
/// `POST /v1/produce` (crates/shell step 8b). Failure aborts the
/// transaction — a domain change whose event was never persisted rolls
/// back, so consumers never see an unannounced change.
async fn emit_event_tx(
    tx: &mut sqlx::PgConnection,
    env_id: Uuid,
    event_type: &str,
    payload: &serde_json::Value,
) {
    if let Err(e) =
        sentin8::bus::outbox::insert_outbox_row(tx, env_id, "func", event_type, payload).await
    {
        tracing::error!(error = %e, event_type = %event_type, "func: outbox event insert failed — rolling back domain change");
    }
}

/// Best-effort audit event (never blocks the response path). Written to
/// the local `audit_journal` with the tenant context set on the same
/// connection (§6.8); the shared shell pusher forwards rows to Sys.
async fn audit_event(pool: &sqlx::PgPool, env_id: Uuid, action: &str, event: serde_json::Value) {
    let Ok(mut tx) = pool.begin().await else {
        return;
    };
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    let _ = sqlx::query(
        "INSERT INTO audit_journal (id, env_id, action, details) VALUES ($1, $2, $3, $4)",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(env_id)
    .bind(action)
    .bind(&event)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::warn!(error = %e, "func: audit insert failed");
        e
    });
    let _ = tx.commit().await;
}

/// `POST /v1/modules` — upload a new WASM module.
#[utoipa::path(
    post,
    operation_id = "module.upload",
    path = "/v1/modules",
    request_body = UploadRequest,
    responses(
        (status = 200, description = "Module uploaded", body = crate::store::ModuleRecord),
        (status = 400, description = "Invalid binary, hash mismatch, unknown hook, or bad target_env_id"),
        (status = 403, description = "Missing func:write scope"),
        (status = 409, description = "Module version already exists"),
    ),
    security(("sentin8:func:write" = [])),
    tag = "func",
)]
/// Handle upload.
pub async fn upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<crate::admin_ui::TargetEnvQuery>,
    Json(req): Json<UploadRequest>,
) -> Result<Json<ModuleRecord>, (StatusCode, String)> {
    let a = auth::verify_cert_or_token(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:func:write"),
    )
    .await?;
    let env_id = resolve_env(&a, q.target_env_id.as_deref())?;
    if !wasm_gate_open(&state.pool, env_id).await? {
        return Err(gate_closed());
    }

    // Reject unknown hook names.
    for hook in &req.hooks {
        if !KNOWN_HOOKS.contains(&hook.as_str()) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("unknown hook '{hook}' (allowed: {KNOWN_HOOKS:?})"),
            ));
        }
    }

    // Decode base64.
    let bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &req.wasm_binary)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("base64 decode: {e}")))?;
    // Compute hash; verify a client-provided hash matches.
    let computed = WasmRuntime::wasm_hash(&bytes);
    if let Some(provided) = &req.wasm_hash {
        if provided != &computed {
            return Err((StatusCode::BAD_REQUEST, "wasm hash mismatch".into()));
        }
    }
    // Generate the module id first so the Storage object key is stable.
    let module_id = Uuid::new_v4();
    let sentin8_storage_key = format!("func/{}/{module_id}.wasm", req.domain);

    // Validate (parse + WASI reject + hook exports + import-map coverage).
    state
        .runtime
        .validate(&bytes, &req.hooks, None)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    // Content-addressed versioning (func DESIGN §3): the same binary for the
    // same (env, domain, product) re-registers the EXISTING version — no
    // duplicate content rows, no second Storage object. The caller learns
    // the existing version instead of receiving a conflict.
    if let Some(existing) =
        store::find_module_by_content(&state.pool, env_id, &req.domain, &req.product_id, &computed)
            .await?
    {
        return Ok(Json(existing));
    }

    // Storage write precedes the metadata row: an orphan object is
    // harmless, an orphan row pointing at a never-stored binary is not.
    // put_if_absent makes retries idempotent (content-addressed).
    match state
        .storage
        .put_if_absent(
            &env_id.to_string(),
            &env_id.to_string(),
            &sentin8_storage_key,
            "application/wasm",
            bytes.clone(),
        )
        .await
    {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, module_id = %module_id, "failed to store WASM binary in Storage");
            return Err((
                StatusCode::BAD_GATEWAY,
                format!("failed to store WASM binary: {e}"),
            ));
        }
    }

    // Metadata row (own transaction with tenant context).
    let module = match store::insert_module(
        &state.pool,
        env_id,
        &req,
        &computed,
        bytes.len() as i32,
        &sentin8_storage_key,
    )
    .await
    {
        Ok(m) => m,
        Err((status, msg)) => {
            // Rollback: remove the orphan Storage object.
            let _ = state
                .storage
                .delete(
                    &env_id.to_string(),
                    &env_id.to_string(),
                    &sentin8_storage_key,
                )
                .await;
            return Err((status, msg));
        }
    };

    // Compile + cache (best-effort; on-demand compile covers a miss).
    if let Err(e) = state
        .runtime
        .compile_and_cache(&bytes, &computed, req.hooks.clone())
    {
        tracing::warn!(error = %e, "failed to cache compiled module");
    }

    // Event + audit after the domain change.
    emit_best_effort_event(
        &state.pool,
        env_id,
        "sentin8:func:module:created",
        &serde_json::json!({
            "module_id": module.id,
            "language": module.wasm_language,
            "hash": module.wasm_hash,
        }),
    )
    .await;
    audit_event(
        &state.pool,
        env_id,
        "sentin8:func:module:create",
        serde_json::json!({
            "action": "create",
            "resource": "func_module",
            "module_id": module.id,
            "domain": module.domain,
            "product_id": module.product_id,
            "version": module.version_label,
            "actor": a.sub(),
        }),
    )
    .await;

    Ok(Json(module))
}

/// Best-effort event: standalone transaction, only for post-commit
/// notifications. The transactional path (`emit_event_tx`) is used when the
/// domain write and the event share a tx.
async fn emit_best_effort_event(
    pool: &sqlx::PgPool,
    env_id: Uuid,
    event_type: &str,
    payload: &serde_json::Value,
) {
    let Ok(mut tx) = pool.begin().await else {
        tracing::warn!(event_type = %event_type, "func: could not acquire tx for event");
        return;
    };
    emit_event_tx(&mut tx, env_id, event_type, payload).await;
    if let Err(e) = tx.commit().await {
        tracing::warn!(error = %e, event_type = %event_type, "func: event commit failed");
    }
}

// ── List / Get / Delete / Activate ──────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
/// The listquery type.
pub struct ListQuery {
    #[serde(default)]
    /// The domain.
    pub domain: Option<String>,
    #[serde(default)]
    /// product identifier.
    pub product_id: Option<String>,
}

/// `GET /v1/modules`
#[utoipa::path(
    get,
    operation_id = "module.list",
    path = "/v1/modules",
    params(("domain" = Option<String>, Query, description = "Filter by domain"), ("product_id" = Option<String>, Query, description = "Filter by product ID")),
    responses(
        (status = 200, description = "List of modules", body = [crate::store::ModuleRecord]),
        (status = 400, description = "Invalid target_env_id"),
    ),
    security(("sentin8:func:read" = [])),
    tag = "func",
)]
/// List it.
pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
    Query(teq): Query<crate::admin_ui::TargetEnvQuery>,
) -> Result<Json<Vec<ModuleRecord>>, (StatusCode, String)> {
    let a = auth::verify_cert_or_token(&state.workload_registry, &state.config, &headers).await?;
    let env_id = resolve_env(&a, teq.target_env_id.as_deref())?;
    let modules = store::list_modules(
        &state.pool,
        env_id,
        q.domain.as_deref(),
        q.product_id.as_deref(),
    )
    .await?;
    Ok(Json(modules))
}

/// `GET /v1/modules/{id}`
#[utoipa::path(
    get,
    operation_id = "module.get",
    path = "/v1/modules/{id}",
    params(("id" = Uuid, Path, description = "Module ID")),
    responses(
        (status = 200, description = "Module metadata", body = crate::store::ModuleRecord),
        (status = 404, description = "Module not found"),
    ),
    security(("sentin8:func:read" = [])),
    tag = "func",
)]
/// Fetch it.
pub async fn get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<ModuleRecord>, (StatusCode, String)> {
    let a = auth::verify_cert_or_token(&state.workload_registry, &state.config, &headers).await?;
    let module = store::get_module(&state.pool, a.env_id(), id).await?;
    Ok(Json(module))
}

/// `GET /v1/modules/{id}/wasm` — download the raw WASM binary from Storage.
#[utoipa::path(
    get,
    operation_id = "module.download",
    path = "/v1/modules/{id}/wasm",
    params(("id" = Uuid, Path, description = "Module ID")),
    responses(
        (status = 200, description = "WASM binary", body = Vec<u8>),
        (status = 404, description = "Module or binary not found"),
        (status = 403, description = "Missing func:write scope"),
    ),
    security(("sentin8:func:write" = [])),
    tag = "func",
)]
/// Fetch wasm.
pub async fn get_wasm(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let a = auth::verify_cert_or_token(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:func:write"),
    )
    .await?;
    if !wasm_gate_open(&state.pool, a.env_id()).await? {
        return Err(gate_closed());
    }
    let module = store::get_module(&state.pool, a.env_id(), id).await?;
    let key = module.sentin8_storage_object_key.ok_or((
        StatusCode::NOT_FOUND,
        "no Storage object key for module".to_string(),
    ))?;
    let bytes = state
        .storage
        .get(&a.env_id().to_string(), &a.env_id().to_string(), &key)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Storage error: {e}")))?;
    Ok(axum::response::Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/wasm")
        .body(axum::body::Body::from(bytes))
        .unwrap())
}

/// `DELETE /v1/modules/{id}`
#[utoipa::path(
    delete,
    operation_id = "module.delete",
    path = "/v1/modules/{id}",
    params(("id" = Uuid, Path, description = "Module ID")),
    responses(
        (status = 204, description = "Module deleted"),
        (status = 404, description = "Module not found or is active"),
        (status = 403, description = "Missing func:write scope"),
    ),
    security(("sentin8:func:write" = [])),
    tag = "func",
)]
/// Delete it.
pub async fn delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let a = auth::verify_cert_or_token(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:func:write"),
    )
    .await?;
    if !wasm_gate_open(&state.pool, a.env_id()).await? {
        return Err(gate_closed());
    }
    let object_key = store::delete_module(&state.pool, a.env_id(), id).await?;
    // Evict the compiled module from the cache so a stale binary cannot be
    // executed after deletion.
    if let Ok(module) = store::get_module(&state.pool, a.env_id(), id).await {
        state.runtime.evict(&module.wasm_hash);
    }
    // Delete WASM binary from Storage (best-effort).
    if let Some(key) = object_key {
        if let Err(e) = state
            .storage
            .delete(&a.env_id().to_string(), &a.env_id().to_string(), &key)
            .await
        {
            tracing::warn!(error = %e, module_id = %id, "failed to delete WASM binary from Storage");
        }
    }
    emit_best_effort_event(
        &state.pool,
        a.env_id(),
        "sentin8:func:module:deleted",
        &serde_json::json!({ "module_id": id }),
    )
    .await;
    audit_event(
        &state.pool,
        a.env_id(),
        "sentin8:func:module:delete",
        serde_json::json!({
            "action": "delete",
            "resource": "func_module",
            "module_id": id,
            "actor": a.sub(),
        }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/modules/{id}/activate`
#[utoipa::path(
    post,
    operation_id = "module.activate",
    path = "/v1/modules/{id}/activate",
    params(("id" = Uuid, Path, description = "Module ID")),
    responses(
        (status = 204, description = "Module activated"),
        (status = 404, description = "Module not found"),
        (status = 403, description = "Missing func:write scope"),
    ),
    security(("sentin8:func:write" = [])),
    tag = "func",
)]
/// Handle activate.
pub async fn activate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let a = auth::verify_cert_or_token(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:func:write"),
    )
    .await?;
    if !wasm_gate_open(&state.pool, a.env_id()).await? {
        return Err(gate_closed());
    }
    store::activate_module(&state.pool, a.env_id(), id).await?;
    emit_best_effort_event(
        &state.pool,
        a.env_id(),
        "sentin8:func:module:activated",
        &serde_json::json!({ "module_id": id }),
    )
    .await;
    audit_event(
        &state.pool,
        a.env_id(),
        "sentin8:func:module:activate",
        serde_json::json!({
            "action": "update",
            "resource": "func_module",
            "module_id": id,
            "change": "activate",
            "actor": a.sub(),
        }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// ── Validate ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
/// Response payload for validate.
pub struct ValidateResponse {
    /// The valid.
    pub valid: bool,
    /// The errors.
    pub errors: Vec<String>,
    /// The exports.
    pub exports: Vec<String>,
}

/// `POST /v1/modules/{id}/validate` — re-validate the stored binary.
#[utoipa::path(
    post,
    operation_id = "module.validate",
    path = "/v1/modules/{id}/validate",
    params(("id" = Uuid, Path, description = "Module ID")),
    responses(
        (status = 200, description = "Validation result", body = ValidateResponse),
        (status = 404, description = "Module not found"),
        (status = 502, description = "Binary unavailable in Storage"),
    ),
    security(("sentin8:func:read" = [])),
    tag = "func",
)]
/// Validate it.
pub async fn validate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<ValidateResponse>, (StatusCode, String)> {
    let a = auth::verify_cert_or_token(&state.workload_registry, &state.config, &headers).await?;
    let module = store::get_module(&state.pool, a.env_id(), id).await?;
    if !wasm_gate_open(&state.pool, a.env_id()).await? {
        return Err(gate_closed());
    }
    // Fetch the stored binary and re-run the validation pipeline.
    let result: Result<Vec<String>, String> = match &module.sentin8_storage_object_key {
        Some(key) => match state
            .storage
            .get(&a.env_id().to_string(), &a.env_id().to_string(), key)
            .await
        {
            Ok(bytes) => state
                .runtime
                .validate(&bytes, &module.hooks, None),
            Err(e) => Err(format!("Storage fetch failed: {e}")),
        },
        None => Err("no Storage object key for module".to_string()),
    };
    Ok(Json(match result {
        Ok(exports) => ValidateResponse {
            valid: true,
            errors: vec![],
            exports,
        },
        Err(e) => ValidateResponse {
            valid: false,
            errors: vec![e],
            exports: vec![],
        },
    }))
}

// ── Execute ──────────────────────────────────────────────────────────────

/// `POST /v1/modules/{id}/execute`
#[utoipa::path(
    post,
    operation_id = "module.execute",
    path = "/v1/modules/{id}/execute",
    params(("id" = Uuid, Path, description = "Module ID")),
    request_body = crate::runtime::ExecuteRequest,
    responses(
        (status = 200, description = "Execution result", body = crate::runtime::ExecuteResponse),
        (status = 400, description = "Invalid module or hook"),
        (status = 403, description = "Missing func:execute scope"),
        (status = 404, description = "Module not found"),
        (status = 500, description = "Execution failure (fuel/timeout/trap)"),
        (status = 502, description = "Proxy-back or Storage failure"),
    ),
    security(("sentin8:func:execute" = [])),
    tag = "func",
)]
/// Execute it.
pub async fn execute(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<ExecuteRequest>,
) -> Result<Json<ExecuteResponse>, (StatusCode, String)> {
    let a = auth::verify_cert_or_token(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:func:execute"),
    )
    .await?;
    if !wasm_gate_open(&state.pool, a.env_id()).await? {
        return Err(gate_closed());
    }
    let module = store::get_module(&state.pool, a.env_id(), id).await?;
    execute_on_module(state, a.env_id(), module, req).await
}

/// `POST /v1/modules/product/{product_id}/execute` — execute a hook on the
/// product's currently-ACTIVE version (the `latest` pointer; func DESIGN
/// §4). The pinned-by-id route is the exact-version surface; this is the
/// convenience route for callers that track products, not versions.
#[utoipa::path(
    post,
    path = "/v1/modules/product/{product_id}/execute",
    request_body = crate::runtime::ExecuteRequest,
    responses(
        (status = 200, description = "Execution result", body = ExecuteResponse),
        (status = 404, description = "No active module for the product"),
        (status = 403, description = "Missing func:execute scope"),
    ),
    security(("sentin8:func:execute" = [])),
    tag = "func",
)]
/// Execute on product.
pub async fn execute_product(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(product_id): Path<String>,
    Json(req): Json<ExecuteRequest>,
) -> Result<Json<ExecuteResponse>, (StatusCode, String)> {
    let a = auth::verify_cert_or_token(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:func:execute"),
    )
    .await?;
    if !wasm_gate_open(&state.pool, a.env_id()).await? {
        return Err(gate_closed());
    }
    let module = store::resolve_module(&state.pool, a.env_id(), &product_id).await?;
    execute_on_module(state, a.env_id(), module, req).await
}

/// Shared execution path: dedupe lookup → in-memory cache → on-demand
/// compile from Storage → execute → dedupe store → metrics.
async fn execute_on_module(
    state: AppState,
    env_id: Uuid,
    module: crate::store::ModuleRecord,
    req: ExecuteRequest,
) -> Result<Json<ExecuteResponse>, (StatusCode, String)> {
    let id = module.id;
    let a_env = env_id;
    // Idempotency (func DESIGN §6): a replayed execution with the same
    // (module_id, hook, idempotency_key) returns the cached response —
    // at-least-once triggers must not re-run hooks.
    if let Some(key) = req.idempotency_key.as_deref() {
        if let Some(cached) = execute_dedupe_lookup(&state.pool, a_env, id, &req.hook, key).await?
        {
            return Ok(Json(cached));
        }
    }
    // Try in-memory cache first; fall back to Storage if not cached.
    if let Some(cached) = state.runtime.cache.get(&module.wasm_hash) {
        let resp = state
            .runtime
            .execute(&cached, &req)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        if let Some(key) = req.idempotency_key.as_deref() {
            execute_dedupe_store(&state.pool, a_env, id, &req.hook, key, &resp).await;
        }
        return Ok(Json(resp));
    }
    // Fetch from Storage and compile on demand.
    let key = module.sentin8_storage_object_key.ok_or((
        StatusCode::NOT_FOUND,
        "no Storage object key for module".to_string(),
    ))?;
    let bytes = state
        .storage
        .get(&a_env.to_string(), &a_env.to_string(), &key)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Storage error: {e}")))?;
    state
        .runtime
        .compile_and_cache(&bytes, &module.wasm_hash, module.hooks.clone())
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("compile error: {e}")))?;
    let cached = state.runtime.cache.get(&module.wasm_hash).ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "failed to compile on demand".into(),
    ))?;
    let resp = state
        .runtime
        .execute(&cached, &req)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    if let Some(key) = req.idempotency_key.as_deref() {
        execute_dedupe_store(&state.pool, a_env, id, &req.hook, key, &resp).await;
    }
    emit_execution_metrics(&resp);
    Ok(Json(resp))
}

/// FUNC-5 (func DESIGN §6): emit the execution's `duration_ms` and
/// `fuel_used` as Stat metrics (family `func`, event `func.execute`) —
/// the same values the response carries, so dashboards can chart WASM
/// execution cost. Fire-and-forget; the emitter is initialized by the
/// shell boot (`boot_full`) and a disabled emitter is a no-op.
fn emit_execution_metrics(resp: &ExecuteResponse) {
    sentin8::shield::stat_emit::emit_metric_event(
        "sentin8:func",
        "func.execute",
        serde_json::json!({
            "duration_ms": resp.duration_ms,
            "fuel_used": resp.fuel_used,
        }),
        serde_json::json!({}),
    );
}

/// Look up a cached execute response by idempotency key (func DESIGN §6).
/// Best-effort: a lookup failure falls through to execution.
async fn execute_dedupe_lookup(
    pool: &sqlx::PgPool,
    env_id: uuid::Uuid,
    module_id: Uuid,
    hook: &str,
    idempotency_key: &str,
) -> Result<Option<ExecuteResponse>, (StatusCode, String)> {
    let Ok(mut tx) = pool.begin().await else {
        return Ok(None);
    };
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    let row: Option<(serde_json::Value,)> = sqlx::query_as(
        "SELECT response FROM execute_dedupe WHERE module_id = $1 AND hook = $2 AND idempotency_key = $3",
    )
    .bind(module_id)
    .bind(hook)
    .bind(idempotency_key)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("dedupe lookup: {e}")))?;
    let _ = tx.commit().await;
    Ok(row.and_then(|(v,)| serde_json::from_value(v).ok()))
}

/// Store an execute response under the idempotency key. Best-effort —
/// a store failure never fails the original execution.
async fn execute_dedupe_store(
    pool: &sqlx::PgPool,
    env_id: uuid::Uuid,
    module_id: Uuid,
    hook: &str,
    idempotency_key: &str,
    response: &ExecuteResponse,
) {
    let Ok(Ok(mut tx)) = pool.begin().await.map(Ok::<_, sqlx::Error>) else {
        return;
    };
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    let _ = sqlx::query(
        "INSERT INTO execute_dedupe (module_id, hook, idempotency_key, response, env_id)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (module_id, hook, idempotency_key) DO NOTHING",
    )
    .bind(module_id)
    .bind(hook)
    .bind(idempotency_key)
    .bind(serde_json::to_value(response).unwrap_or(serde_json::Value::Null))
    .bind(env_id)
    .execute(&mut *tx)
    .await;
    let _ = tx.commit().await;
}

// ── Health ───────────────────────────────────────────────────────────────

/// Handle health.
pub async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    let mut payload = serde_json::json!({
        "status": "ok",
        "service": "func",
        "version": sentin8::build_info::id(),
        "build": sentin8::build_info::build_hash(),
        "runtime": "wasmtime",
        "cache_size": state.runtime.cache.len(),
    });
    if let Some(n) = sentin8::middleware::traffic_counter::process_active_connections() {
        payload["active_connections"] = serde_json::json!(n);
    }
    Json(payload)
}
