// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Func
// SPDX-License-Identifier: Apache-2.0

//! Func configuration loaded from environment variables.

use std::env;

use sentin8::auth::client::{Client as AuthClient, ClientOptions};

#[derive(Debug, Clone)]
/// Configuration for func.
pub struct FuncConfig {
    /// The port.
    pub port: u16,
    /// The database URL.
    pub database_url: String,
    /// The sentin8 auth issuer.
    pub sentin8_auth_issuer: String,
    /// The sentin8 auth JWKS URL.
    pub sentin8_auth_jwks_url: String,
    /// The sentin8 storage URL.
    pub sentin8_storage_url: String,
    /// Max wasmtime fuel per invocation (100M instructions).
    /// Maximum fuel.
    pub max_fuel: u64,
    /// Max WASM linear memory in bytes (16 MiB).
    /// Maximum memory bytes.
    pub max_memory_bytes: usize,
    /// Wall-clock timeout per invocation in milliseconds (5000).
    /// The timeout ms.
    pub timeout_ms: u64,
    /// Max module cache size.
    /// The cache max modules.
    pub cache_max_modules: usize,
    /// Shared Auth client — constructed once so the discovery and JWKS
    /// caches are reused across every request (5-minute TTL each).
    /// Cloning is cheap (the caches live behind an `Arc`).
    /// The auth client.
    pub auth_client: AuthClient,
    /// Bus base URL for event publication.
    /// The sentin8 bus URL.
    pub sentin8_bus_url: String,
    /// Bus stream family for Func events (default `"func"`).
    /// The stream family.
    pub stream_family: String,
}

impl FuncConfig {
    /// Handle from env.
    pub fn from_env() -> Self {
        let cfg = sentin8::config::Sentin8Config::from_env();
        Self {
            port: env::var("SENTIN8_FUNC_PORT")
                .expect("SENTIN8_FUNC_PORT must be set by captain")
                .parse()
                .expect("SENTIN8_FUNC_PORT must be a valid u16"),
            database_url: env::var("SENTIN8_FUNC_DATABASE_URL").unwrap_or_else(|_| {
                env::var("DATABASE_URL").unwrap_or_else(|_| {
                    sentin8::config::Sentin8Config::default_database_url().to_string()
                })
            }),
            sentin8_auth_issuer: env::var("SENTIN8_AUTH_ISSUER")
                .unwrap_or_else(|_| cfg.sentin8_auth_issuer()),
            sentin8_auth_jwks_url: env::var("SENTIN8_AUTH_JWKS_URL")
                .unwrap_or_else(|_| cfg.sentin8_auth_jwks_url()),
            sentin8_storage_url: env::var("SENTIN8_STORAGE_URL")
                .unwrap_or_else(|_| cfg.sentin8_storage_url()),
            max_fuel: env::var("SENTIN8_FUNC_MAX_FUEL")
                .unwrap_or("100000000".into())
                .parse()
                .unwrap_or(100_000_000),
            max_memory_bytes: env::var("SENTIN8_FUNC_MAX_MEMORY_BYTES")
                .unwrap_or("16777216".into())
                .parse()
                .unwrap_or(16 * 1024 * 1024),
            timeout_ms: env::var("SENTIN8_FUNC_TIMEOUT_MS")
                .unwrap_or("5000".into())
                .parse()
                .unwrap_or(5000),
            cache_max_modules: env::var("SENTIN8_FUNC_CACHE_MAX")
                .unwrap_or("100".into())
                .parse()
                .unwrap_or(100),
            auth_client: AuthClient::new(ClientOptions {
                base_url: env::var("SENTIN8_AUTH_ISSUER")
                    .unwrap_or_else(|_| cfg.sentin8_auth_issuer()),
                ..Default::default()
            }),
            sentin8_bus_url: env::var("SENTIN8_BUS_URL").unwrap_or_else(|_| cfg.sentin8_bus_url()),
            stream_family: env::var("SENTIN8_FUNC_STREAM_FAMILY").unwrap_or_else(|_| "func".into()),
        }
    }
}
