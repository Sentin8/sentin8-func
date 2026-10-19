// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Func
// SPDX-License-Identifier: Apache-2.0

//! Annotated RFW alias wrappers (Dash 28.14 - the RFW renderer is
//! POST-only): one annotated handler = one path in the spec, so a second
//! binding of `handlers::delete` needs its own annotated wrapper (same
//! handler body, alias path - OAPEC design §2 rule 3).

use crate::handlers::AppState;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};

/// `POST /v1/modules/{id}/delete` - RFW alias of `DELETE /v1/modules/{id}`.
#[utoipa::path(
    post,
    path = "/v1/modules/{id}/delete",
    params(("id" = uuid::Uuid, Path, description = "Module id")),
    responses(
        (status = 204, description = "Module deleted (same contract as DELETE /v1/modules/{id})"),
        (status = 404, description = "Unknown module"),
        (status = 409, description = "Module is ACTIVE - deprecate first"),
        (status = 401, description = "Caller authentication failed"),
        (status = 403, description = "Missing func:write scope"),
    ),
    security(("sentin8:func:write" = [])),
    tag = "func",
)]
pub async fn module_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    crate::handlers::delete(State(state), headers, Path(id)).await
}