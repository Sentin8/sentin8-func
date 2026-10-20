// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Func
// SPDX-License-Identifier: Apache-2.0

//! Axum server setup for Func.

use std::sync::Arc;

use axum::routing::{get, post};

use crate::handlers::{self, AppState};
use crate::runtime::WasmRuntime;

/// Build state.
pub async fn build_state(
    core: sentin8::shell::ServiceCore,
) -> anyhow::Result<crate::handlers::AppState> {
    let config = crate::config::FuncConfig::from_env();
    let runtime = WasmRuntime::new(
        config.max_fuel,
        config.max_memory_bytes,
        config.timeout_ms,
        config.cache_max_modules,
    )?;

    // Storage client - CERT-PRESENTING (auth DESIGN §4.3f):
    // ensure the `func-storage` workload CERTIFICATE (load-or-mint from
    // Acme - the certificate IS the identity; no DCR, no token) and build
    // the cert-presenting client. Storage's TLS layer authenticates the
    // handshake; the registry map authorizes the scopes.
    let ca_cert_path = sentin8::auth::m2m::platform_ca_path();
    let storage = sentin8::auth::m2m::ensure_workload_certificate(
        &config.sentin8_auth_issuer,
        "func-storage",
        &ca_cert_path,
    )
    .await
    .and_then(|cert| {
        sentin8_storage_sdk::client::StorageClient::with_workload_identity(
            &config.sentin8_storage_url,
            &cert.ca_cert_path,
            &cert.cert_path,
            &cert.key_path,
        )
        .map_err(|e| sentin8::auth::m2m::M2mError::Cert(e.to_string()))
    })
    .map_err(|e| {
        tracing::warn!(error = %e, "func: Storage cert-presenting client build failed");
        e
    })
    .ok()
    .unwrap_or_else(|| {
        // Fail-soft dev fallback: a plain transport (Storage rejects it
        // loudly) rather than aborting boot - the certificate mint can
        // succeed on the next restart once Acme is up.
        tracing::warn!("func: Storage client falling back to a plain transport (no identity)");
        sentin8_storage_sdk::client::StorageClient::new_dev_plain(&config.sentin8_storage_url)
    });

    // Startup cache warm-up: fetch all active modules from DB, fetch their
    // binaries from Storage, and compile into the in-memory cache.
    match crate::store::list_all_active_modules(&core.pool).await {
        Ok(active) if !active.is_empty() => {
            tracing::info!(count = active.len(), "warming WASM cache from Storage");
            for m in &active {
                if let Some(key) = &m.sentin8_storage_object_key {
                    match storage
                        .get(&m.env_id.to_string(), &m.env_id.to_string(), key)
                        .await
                    {
                        Ok(bytes) => {
                            if let Err(e) =
                                runtime.compile_and_cache(&bytes, &m.wasm_hash, m.hooks.clone())
                            {
                                tracing::warn!(module_id = %m.id, error = %e, "failed to compile module during warm-up");
                            }
                        }
                        Err(e) => {
                            tracing::warn!(module_id = %m.id, error = %e, "failed to fetch module from Storage during warm-up");
                        }
                    }
                }
            }
        }
        Ok(_) => tracing::info!("no active modules to warm"),
        Err(e) => tracing::warn!(error = %e.1, "failed to list active modules for warm-up"),
    }

    // ── Sentin8:Policy (- shell-owned boot): consume the
    // engine the shell booted in step 8 - no second engine, consumer, or
    // DCR registration here.
    let policy_engine = core.admin.policy.clone();

    let state = AppState {
        config: Arc::new(config.clone()),
        pool: core.pool.clone(),
        runtime,
        storage,
        // auth DESIGN §4.3f: boot-load the workload registry map (the
        // token-free authorization record) for the cert-first handler
        // gate. Fail-open-with-warning on an unreachable Valkey at boot -
        // the bearer path (user/delegated) serves while
        // certificate-workload calls fail-closed until the next boot
        // (the map is normally published by enroll BEFORE services
        // start). The load presents THIS service's certificate identity
        // over the Valkey TLS plane (group DESIGN.md §3.1).
        workload_registry: match sentin8::auth::workload_registry::WorkloadMap::boot_load(
            "sentin8:func",
        )
        .await
        {
            Ok(map) => map,
            Err(e) => {
                tracing::warn!(error = %e, "func: workload registry map unavailable at boot - certificate-workload calls fail-closed until next boot");
                sentin8::auth::workload_registry::WorkloadMap::boot_load_empty("sentin8:func")
            }
        },
        policy: policy_engine.clone(),
        admin: sentin8::shield::admin::SharedAdminState {
            service: "sentin8:func".to_string(),
            pool: core.pool.clone(),
            policy: policy_engine.clone(),
            auth_client: Arc::new(config.auth_client.clone()),
        },
    };

    Ok(state)
}

/// Add this service's routes onto the shell-provided router. The shell
/// owns the boot sequence, state binding, OpenAPI merge and the standard
/// middleware stack; this adds ONLY routes (including the service's own
/// `/v1/health` - custom payload).
/// Handle routes.
pub fn routes(
    router: axum::Router<crate::handlers::AppState>,
) -> axum::Router<crate::handlers::AppState> {
    router
        .route("/v1/health", get(handlers::health))
        // ── Admin UI (RFW) ─────────────────────────────────────────────────
        .route("/v1/admin/ui/{*page}", get(crate::admin_ui::get_admin_ui))
        .route("/v1/admin/{resource}", get(crate::admin_ui::get_admin_data))
        .route("/v1/modules", post(handlers::upload).get(handlers::list))
        .route(
            "/v1/modules/{id}",
            get(handlers::get).delete(handlers::delete),
        )
        // POST alias for RFW row_action_post (renderer only supports POST)
        .route(
            "/v1/modules/{id}/delete",
            post(crate::rfw_aliases::module_delete),
        )
        .route("/v1/modules/{id}/wasm", get(handlers::get_wasm))
        .route("/v1/modules/{id}/validate", post(handlers::validate))
        .route("/v1/modules/{id}/activate", post(handlers::activate))
        .route("/v1/modules/{id}/execute", post(handlers::execute))
        .route(
            "/v1/modules/product/{product_id}/execute",
            post(handlers::execute_product),
        )
        // Traffic counter - counts every inbound request (excludes health checks).
        // ── Sentin8:Policy admin API ( - shared implementation,
        // one surface per service; handlers are generic over this AppState).
        .route(
            "/v1/admin/policy-sets",
            get(sentin8::shield::admin::list_policy_sets::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}",
            get(sentin8::shield::admin::get_policy_set::<handlers::AppState>)
                .put(sentin8::shield::admin::put_policy_set::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}/test",
            post(sentin8::shield::admin::test_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/enforce",
            post(sentin8::shield::admin::admin_enforce_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/shadow",
            post(sentin8::shield::admin::admin_shadow_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/disable",
            post(sentin8::shield::admin::admin_disable_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/relations",
            get(sentin8::shield::admin::list_relations::<handlers::AppState>)
                .put(sentin8::shield::admin::put_relation::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_relation::<handlers::AppState>),
        )
        .route(
            "/v1/admin/relations/check",
            get(sentin8::shield::admin::check_relation::<handlers::AppState>),
        )
        .route(
            "/v1/admin/attributes",
            get(sentin8::shield::admin::list_attributes::<handlers::AppState>)
                .put(sentin8::shield::admin::put_attribute::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_attribute::<handlers::AppState>),
        )
}

/// Shared policy-admin surface accessor - the shared
/// handlers extract this service's admin state via [`HasPolicyAdmin`].
impl sentin8::shield::admin::HasPolicyAdmin for AppState {
    fn policy_admin(&self) -> &sentin8::shield::admin::SharedAdminState {
        &self.admin
    }
}
