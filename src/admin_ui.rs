// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Func
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:Func Admin UI handlers - RFW definitions.
//! Served from `GET /v1/admin/ui/{page}`, rendered by Sentin8:Dash at runtime.

use crate::handlers::AppState;
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use sentin8::rfw::page::*;
use sentin8::rfw::response::AdminUiResponse;
use sentin8::rfw::widget::*;
use serde::Deserialize;
use sqlx::Row;

#[derive(Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
/// The targetenvquery type.
pub struct TargetEnvQuery {
    #[serde(default)]
    /// target env identifier.
    pub target_env_id: Option<String>,
}

/// Fetch admin ui.
#[utoipa::path(
    get,
    path = "/v1/admin/ui/{page}",
    params(
        ("page" = String, Path, description = "RFW page name"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "RFW page definition (rendered by Sentin8:Dash)", body = serde_json::Value),
        (status = 403, description = "Caller lacks a func read/admin scope"),
        (status = 404, description = "Unknown page"),
    ),
    security(("sentin8:func:write" = [])),
    tag = "admin-ui",
)]
pub async fn get_admin_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(_q): Query<TargetEnvQuery>,
    Path(page): Path<String>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    a.require_any_scope(&[
        "sentin8:func:write",
        "sentin8:func:execute",
        "sentin8:sys:admin",
        "sentin8:sys:org:admin",
        "sentin8:sys:env:admin",
    ])?;
    let def = match page.as_str() {
        "overview" => AdminPage::new("Func Overview")
            .widget(card(
                "Summary",
                "Active modules, executions today, error rate.",
            ))
            .build(),
        "versions" => AdminPage::new("Module Versions")
            .action(link("Upload Module", "versions/new"))
            .widget(table_with_actions(
                vec![
                    col("id", "Module ID"),
                    cols("name", "Name"),
                    cols("version", "Version"),
                    cols("status", "Status"),
                ],
                "/modules",
                vec![
                    row_action_post("Activate", "modules/{id}/activate"),
                    row_action_post("Delete", "modules/{id}/delete"),
                ],
            ))
            .build(),
        "versions/new" => AdminPage::new("Upload Module")
            .widget(RemoteWidget::Form(WidgetForm {
                fields: vec![
                    WidgetFormField {
                        key: "domain".into(),
                        label: "Domain".into(),
                        field_type: FormFieldType::Text,
                        required: true,
                        placeholder: Some("e.g. ledger".into()),
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: Some(
                            "The domain this module belongs to (ledger, payments, etc.).".into(),
                        ),
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "product_id".into(),
                        label: "Product ID".into(),
                        field_type: FormFieldType::Text,
                        required: true,
                        placeholder: Some("e.g. current_account".into()),
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "version_label".into(),
                        label: "Version Label".into(),
                        field_type: FormFieldType::Text,
                        required: true,
                        placeholder: Some("e.g. v1.0.0".into()),
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "wasm_binary".into(),
                        label: "WASM Binary (base64)".into(),
                        field_type: FormFieldType::Text,
                        required: true,
                        placeholder: Some("Base64-encoded WASM binary".into()),
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: Some("Paste the base64-encoded WASM binary here.".into()),
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "wasm_language".into(),
                        label: "Language".into(),
                        field_type: FormFieldType::Select,
                        required: true,
                        placeholder: None,
                        default_value: Some(serde_json::json!("typescript")),
                        options: Some(vec![
                            FormFieldOption {
                                value: "typescript".into(),
                                label: "TypeScript".into(),
                            },
                            FormFieldOption {
                                value: "rust".into(),
                                label: "Rust".into(),
                            },
                        ]),
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                ],
                submit_endpoint: "/v1/modules".into(),
                submit_label: "Upload Module".into(),
                cancel_label: "Cancel".into(),
                method: FormMethod::Post,
            }))
            .build(),
        // ── Policy Studio - shared page
        // constructors; the guard guarantees `Some` ( dispatch).
        p if sentin8::rfw::policy_page("sentin8:func", p).is_some() => {
            sentin8::rfw::policy_page("sentin8:func", p)
                .expect("policy_page checked in guard")
                .build()
        }
        _ => {
            return Err((
                axum::http::StatusCode::NOT_FOUND,
                format!("Unknown admin UI page: {page}"),
            ))
        }
    };
    Ok(Json(
        serde_json::to_value(AdminUiResponse::page(def)).unwrap(),
    ))
}

/// `GET /v1/admin/{resource}` - returns a JSON array of admin data rows.
/// Fetch admin data.
#[utoipa::path(
    get,
    path = "/v1/admin/{resource}",
    params(
        ("resource" = String, Path, description = "Admin data resource"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "The resource's rows for the RFW table", body = serde_json::Value),
        (status = 403, description = "Caller lacks a func read/admin scope"),
        (status = 404, description = "Unknown resource"),
    ),
    security(("sentin8:func:write" = [])),
    tag = "admin-ui",
)]
pub async fn get_admin_data(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(resource): Path<String>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    a.require_any_scope(&[
        "sentin8:func:write",
        "sentin8:func:execute",
        "sentin8:sys:admin",
        "sentin8:sys:org:admin",
        "sentin8:sys:env:admin",
    ])?;
    // target_env_id is required - no fallback to the caller's env.
    let env_id = q
        .target_env_id
        .as_deref()
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| {
            (
                axum::http::StatusCode::BAD_REQUEST,
                "missing or invalid target_env_id".into(),
            )
        })?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    let rows: Vec<serde_json::Value> = match resource.as_str() {
        "modules" => sqlx::query("SELECT id::text, domain, product_id, version_label, status FROM modules WHERE env_id = $1 ORDER BY created_at DESC LIMIT 100")
            .bind(env_id)
            .fetch_all(&mut *tx).await
            .map(|rows| rows.iter().map(|row| serde_json::json!({
                "id": row.get::<Option<String>, &str>("id").unwrap_or_default(),
                "name": row.get::<Option<String>, &str>("domain").unwrap_or_default(),
                "product_id": row.get::<Option<String>, &str>("product_id").unwrap_or_default(),
                "version": row.get::<Option<String>, &str>("version_label").unwrap_or_default(),
                "status": row.get::<Option<String>, &str>("status").unwrap_or_default(),
            })).collect()).unwrap_or_default(),
        _ => vec![],
    };
    tx.commit()
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(serde_json::Value::Array(rows)))
}

fn col(key: &str, label: &str) -> WidgetDataTableColumn {
    WidgetDataTableColumn {
        key: key.into(),
        label: label.into(),
        sortable: false,
        width: None,
        format: None,
    }
}
fn cols(key: &str, label: &str) -> WidgetDataTableColumn {
    WidgetDataTableColumn {
        key: key.into(),
        label: label.into(),
        sortable: true,
        width: None,
        format: None,
    }
}
#[allow(dead_code)]
fn table(columns: Vec<WidgetDataTableColumn>, endpoint: &str) -> RemoteWidget {
    RemoteWidget::DataTable(WidgetDataTable {
        columns,
        data_endpoint: endpoint.into(),
        sortable: true,
        filterable: true,
        page_size: 20,
        empty_message: Some("No data.".into()),
        row_link: None,
        row_actions: vec![],
    })
}
fn table_with_actions(
    columns: Vec<WidgetDataTableColumn>,
    endpoint: &str,
    row_actions: Vec<WidgetButton>,
) -> RemoteWidget {
    RemoteWidget::DataTable(WidgetDataTable {
        columns,
        data_endpoint: endpoint.into(),
        sortable: true,
        filterable: true,
        page_size: 20,
        empty_message: Some("No data.".into()),
        row_link: None,
        row_actions,
    })
}
#[allow(dead_code)]
fn row_action(label: &str, route: &str) -> WidgetButton {
    WidgetButton {
        label: label.into(),
        button_type: ButtonType::Link,
        route: Some(route.into()),
        endpoint: None,
        icon: None,
    }
}
fn row_action_post(label: &str, endpoint: &str) -> WidgetButton {
    WidgetButton {
        label: label.into(),
        button_type: ButtonType::Primary,
        route: None,
        endpoint: Some(endpoint.into()),
        icon: None,
    }
}
fn card(title: &str, body: &str) -> RemoteWidget {
    RemoteWidget::Card(WidgetCard {
        title: Some(title.into()),
        subtitle: None,
        children: vec![RemoteWidget::Text(WidgetText {
            text: body.into(),
            text_type: WidgetTextType::Body,
            align: TextAlign::Left,
            max_lines: None,
        })],
        actions: vec![],
    })
}
#[allow(dead_code)]
fn link(label: &str, route: &str) -> AdminUiAction {
    AdminUiAction {
        label: label.into(),
        action_type: AdminUiActionType::Link,
        route: Some(route.into()),
        endpoint: None,
        icon: Some("add".into()),
    }
}
