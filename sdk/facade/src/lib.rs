//! sentin8-func-sdk — per-service SDK mini-facade (SDD §3.1).
//!
//! Re-exports the service's client + contracts crates. No logic, no
//! features (SDD-4b). Consumers import as `use sentin8_func_sdk::{client|contracts}::…`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// func-client — HTTP client (re-export).
pub mod client {
    pub use sentin8_func_client::*;
}
