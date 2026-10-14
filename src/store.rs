// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Func
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL store for Func module metadata.
//!
//! Every operation runs inside an explicit transaction with the tenant
//! context set on the SAME transaction connection: `sentin8_set_tenant_context`
//! uses `set_config(..., true)` which is transaction-local — setting it on a
//! pooled autocommit connection evaporates before the next statement,
//! silently disabling RLS under the per-service NOBYPASSRLS role.

use sqlx::{PgPool, Row};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, serde::Serialize, ToSchema)]
/// Persisted module record.
pub struct ModuleRecord {
    /// Identifier.
    pub id: Uuid,
    /// The domain.
    pub domain: String,
    /// product identifier.
    pub product_id: String,
    /// The version label.
    pub version_label: String,
    /// The wasm hash.
    pub wasm_hash: String,
    /// The wasm size.
    pub wasm_size: i32,
    /// The wasm language.
    pub wasm_language: String,
    /// The hooks.
    pub hooks: Vec<String>,
    /// The parameters.
    pub parameters: serde_json::Value,
    /// The description.
    pub description: Option<String>,
    /// The status.
    pub status: String,
    /// The sentin8 storage object key.
    pub sentin8_storage_object_key: Option<String>,
    /// env identifier.
    pub env_id: Uuid,
    /// created time.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

fn err_db(e: sqlx::Error) -> (axum::http::StatusCode, String) {
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        format!("db error: {e}"),
    )
}

/// Set the tenant context on a transaction connection. MUST be called after
/// `pool.begin` and before any statement on that connection — the context
/// is transaction-local (`set_config(..., true)`).
async fn set_rls(
    conn: &mut sqlx::PgConnection,
    env_id: Uuid,
) -> Result<(), (axum::http::StatusCode, String)> {
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(conn)
        .await
        .map_err(err_db)?;
    Ok(())
}

fn duplicate_check(e: sqlx::Error) -> (axum::http::StatusCode, String) {
    if e.to_string().contains("duplicate") || e.to_string().contains("unique") {
        (
            axum::http::StatusCode::CONFLICT,
            format!("module version already exists: {e}"),
        )
    } else {
        err_db(e)
    }
}

/// Handle insert module.
pub async fn insert_module(
    pool: &PgPool,
    env_id: Uuid,
    req: &crate::handlers::UploadRequest,
    wasm_hash: &str,
    wasm_size: i32,
    sentin8_storage_object_key: &str,
) -> Result<ModuleRecord, (axum::http::StatusCode, String)> {
    let mut tx = pool.begin().await.map_err(err_db)?;
    set_rls(&mut tx, env_id).await?;
    let row = sqlx::query(
        r#"INSERT INTO modules
           (domain, product_id, version_label, wasm_hash, wasm_size, wasm_language,
            hooks, parameters, description, status, sentin8_storage_object_key, env_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'draft', $10, $11)
           RETURNING id, domain, product_id, version_label, wasm_hash, wasm_size,
                     wasm_language, hooks, parameters, description, status,
                     sentin8_storage_object_key, env_id, created_at"#,
    )
    .bind(&req.domain)
    .bind(&req.product_id)
    .bind(&req.version_label)
    .bind(wasm_hash)
    .bind(wasm_size)
    .bind(&req.wasm_language)
    .bind(&req.hooks)
    .bind(&req.parameters)
    .bind(req.description.as_deref())
    .bind(sentin8_storage_object_key)
    .bind(env_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(duplicate_check)?;
    tx.commit().await.map_err(err_db)?;
    Ok(row_to_module(row))
}

/// List modules.
pub async fn list_modules(
    pool: &PgPool,
    env_id: Uuid,
    domain: Option<&str>,
    product_id: Option<&str>,
) -> Result<Vec<ModuleRecord>, (axum::http::StatusCode, String)> {
    let mut tx = pool.begin().await.map_err(err_db)?;
    set_rls(&mut tx, env_id).await?;
    let rows = sqlx::query(
        r#"SELECT id, domain, product_id, version_label, wasm_hash, wasm_size,
                  wasm_language, hooks, parameters, description, status,
                  sentin8_storage_object_key, env_id, created_at
           FROM modules
           WHERE env_id = $1
             AND ($2::text IS NULL OR domain = $2)
             AND ($3::text IS NULL OR product_id = $3)
           ORDER BY created_at DESC"#,
    )
    .bind(env_id)
    .bind(domain)
    .bind(product_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(err_db)?;
    tx.commit().await.map_err(err_db)?;
    Ok(rows.into_iter().map(row_to_module).collect())
}

/// Resolve a module for EXECUTION by reference. `reference` is either a
/// module UUID (a pinned version) or a `product_id` (resolves the
/// currently-active version of that product — the `latest` pointer; the
/// active-status unique index guarantees at most one match). Execution
/// callers address modules either way (func DESIGN §4).
pub async fn resolve_module(
    pool: &PgPool,
    env_id: Uuid,
    reference: &str,
) -> Result<ModuleRecord, (axum::http::StatusCode, String)> {
    if let Ok(uuid) = Uuid::parse_str(reference) {
        return get_module(pool, env_id, uuid).await;
    }
    let mut tx = pool.begin().await.map_err(err_db)?;
    set_rls(&mut tx, env_id).await?;
    let row = sqlx::query(
        r#"SELECT id, domain, product_id, version_label, wasm_hash, wasm_size,
                  wasm_language, hooks, parameters, description, status,
                  sentin8_storage_object_key, env_id, created_at
           FROM modules
           WHERE env_id = $1 AND product_id = $2 AND status = 'active'"#,
    )
    .bind(env_id)
    .bind(reference)
    .fetch_optional(&mut *tx)
    .await
    .map_err(err_db)?
    .ok_or((
        axum::http::StatusCode::NOT_FOUND,
        format!("no active module for product '{reference}'"),
    ))?;
    tx.commit().await.map_err(err_db)?;
    Ok(row_to_module(row))
}

/// Find an existing row with IDENTICAL content (wasm_hash) for the same
/// (env, domain, product). Version identity is CONTENT-addressed (func
/// DESIGN §3): re-uploading the same binary re-registers that version
/// under the new label instead of storing duplicate content.
pub async fn find_module_by_content(
    pool: &PgPool,
    env_id: Uuid,
    domain: &str,
    product_id: &str,
    wasm_hash: &str,
) -> Result<Option<ModuleRecord>, (axum::http::StatusCode, String)> {
    let mut tx = pool.begin().await.map_err(err_db)?;
    set_rls(&mut tx, env_id).await?;
    let row = sqlx::query(
        r#"SELECT id, domain, product_id, version_label, wasm_hash, wasm_size,
                  wasm_language, hooks, parameters, description, status,
                  sentin8_storage_object_key, env_id, created_at
           FROM modules
           WHERE env_id = $1 AND domain = $2 AND product_id = $3
             AND wasm_hash = $4"#,
    )
    .bind(env_id)
    .bind(domain)
    .bind(product_id)
    .bind(wasm_hash)
    .fetch_optional(&mut *tx)
    .await
    .map_err(err_db)?;
    tx.commit().await.map_err(err_db)?;
    Ok(row.map(row_to_module))
}

/// Fetch a single module by id (the pinned-version read path).
pub async fn get_module(
    pool: &PgPool,
    env_id: Uuid,
    id: Uuid,
) -> Result<ModuleRecord, (axum::http::StatusCode, String)> {
    let mut tx = pool.begin().await.map_err(err_db)?;
    set_rls(&mut tx, env_id).await?;
    let row = sqlx::query(
        r#"SELECT id, domain, product_id, version_label, wasm_hash, wasm_size,
                  wasm_language, hooks, parameters, description, status,
                  sentin8_storage_object_key, env_id, created_at
           FROM modules WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(err_db)?
    .ok_or((axum::http::StatusCode::NOT_FOUND, "module not found".into()))?;
    tx.commit().await.map_err(err_db)?;
    Ok(row_to_module(row))
}

/// Handle activate module.
pub async fn activate_module(
    pool: &PgPool,
    env_id: Uuid,
    id: Uuid,
) -> Result<(), (axum::http::StatusCode, String)> {
    let mut tx = pool.begin().await.map_err(err_db)?;
    set_rls(&mut tx, env_id).await?;
    // Deactivate any currently-active module for the same domain+product.
    sqlx::query(
        r#"UPDATE modules SET status = 'deprecated', updated_at = now()
           WHERE env_id = $1 AND status = 'active'
             AND domain = (SELECT domain FROM modules WHERE id = $2)
             AND product_id = (SELECT product_id FROM modules WHERE id = $2)"#,
    )
    .bind(env_id)
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(err_db)?;
    let res = sqlx::query("UPDATE modules SET status = 'active', updated_at = now() WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
    tx.commit().await.map_err(err_db)?;
    if res.rows_affected() == 0 {
        return Err((axum::http::StatusCode::NOT_FOUND, "module not found".into()));
    }
    Ok(())
}

/// Delete module.
pub async fn delete_module(
    pool: &PgPool,
    env_id: Uuid,
    id: Uuid,
) -> Result<Option<String>, (axum::http::StatusCode, String)> {
    let mut tx = pool.begin().await.map_err(err_db)?;
    set_rls(&mut tx, env_id).await?;
    // Fetch the sentin8_storage_object_key before deleting the row.
    let row = sqlx::query("SELECT sentin8_storage_object_key FROM modules WHERE id = $1 AND status IN ('draft', 'deprecated')")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(err_db)?;
    if row.is_none() {
        return Err((
            axum::http::StatusCode::NOT_FOUND,
            "module not found or is active".into(),
        ));
    }
    let object_key: Option<String> = row.and_then(|r| r.get("sentin8_storage_object_key"));
    let res =
        sqlx::query("DELETE FROM modules WHERE id = $1 AND status IN ('draft', 'deprecated')")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(err_db)?;
    tx.commit().await.map_err(err_db)?;
    if res.rows_affected() == 0 {
        return Err((
            axum::http::StatusCode::NOT_FOUND,
            "module not found or is active".into(),
        ));
    }
    Ok(object_key)
}

fn row_to_module(r: sqlx::postgres::PgRow) -> ModuleRecord {
    ModuleRecord {
        id: r.get("id"),
        domain: r.get("domain"),
        product_id: r.get("product_id"),
        version_label: r.get("version_label"),
        wasm_hash: r.get("wasm_hash"),
        wasm_size: r.get("wasm_size"),
        wasm_language: r.get("wasm_language"),
        hooks: r.get("hooks"),
        parameters: r.get("parameters"),
        description: r.get("description"),
        status: r.get("status"),
        sentin8_storage_object_key: r.get("sentin8_storage_object_key"),
        env_id: r.get("env_id"),
        created_at: r.get("created_at"),
    }
}

/// List all active modules across all orgs/envs — used for startup cache warm-up.
/// Bypasses RLS (runs as platform role).
/// List all active modules.
pub async fn list_all_active_modules(
    pool: &PgPool,
) -> Result<Vec<ModuleRecord>, (axum::http::StatusCode, String)> {
    let rows = sqlx::query(
        r#"SELECT id, domain, product_id, version_label, wasm_hash, wasm_size,
                  wasm_language, hooks, parameters, description, status,
                  sentin8_storage_object_key, env_id, created_at
           FROM modules WHERE status = 'active'
           ORDER BY created_at DESC"#,
    )
    .fetch_all(pool)
    .await
    .map_err(err_db)?;
    Ok(rows.into_iter().map(row_to_module).collect())
}
