// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Func
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 Func server — library re-exports for integration tests.

#![deny(missing_docs)]

/// Admin UI (RFW) handlers.
pub mod admin_ui;
/// Produce/consume authentication helpers.
pub mod auth;
/// Environment configuration.
pub mod config;
/// HTTP handlers — module lifecycle, execution.
pub mod handlers;
/// OpenAPI spec assembly.
pub mod openapi;
/// Shield (Sentin8:Policy) integration — shared bridge re-exports.
pub mod policy;
/// Service self-registration declarations.
pub mod registration;
/// The WASM runtime (wasmtime, gas limits, host functions).
pub mod runtime;
/// Axum router and server.
pub mod server;
/// Module storage (PostgreSQL + object storage).
pub mod store;
