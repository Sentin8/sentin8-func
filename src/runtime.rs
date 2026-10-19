// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Func
// SPDX-License-Identifier: Apache-2.0

//! Wasmtime runtime for the Func WASM execution engine.
//!
//! Implements the full hook ABI from the SDK
//! (`sdk/rust/sentin8/func`, DEVELOPER_GUIDE ):
//!
//! - Hook exports have signature `(req_ptr: i32, req_len: i32) -> i32` and
//!   return a pointer to a JSON `HookResponse` written by the module (via
//!   the module's own `write_response` helper into module-owned memory).
//! - The host serializes the `ExecuteRequest.context` to JSON, allocates
//!   module memory through the module-imported `malloc`, writes the bytes,
//!   calls the hook, reads the response JSON from the returned pointer
//!   (JSON-delimiter scan - see `read_response_json`), and frees both
//!   buffers via `free`.
//! - Built-in host functions (`log`, `util_*`, `malloc`, `free`) are
//!   computed locally; any other import is registered dynamically from the
//!   execute request's `callback_config.host_functions` map and resolved
//!   via authenticated HTTP proxy-back (2 s timeout, 1 MiB response cap).
//!
//! Sandbox: fuel metering (instruction cap), a `ResourceLimiter` memory cap,
//! and a wall-clock deadline via wasmtime epoch interruption. A fresh
//! `Store` is created per invocation; compiled modules are shared via the
//! LRU cache.
//!
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;
use wasmtime::*;

/// A compiled WASM module cached by hash.
/// The cachedmodule type.
pub struct CachedModule {
    /// The hash.
    pub hash: String,
    /// The module.
    pub module: Module,
    /// The hooks.
    pub hooks: Vec<String>,
}

/// LRU cache of compiled modules with true LRU order bookkeeping.
/// The modulecache type.
pub struct ModuleCache {
    max: usize,
    entries: std::sync::Mutex<Vec<Arc<CachedModule>>>,
}

impl ModuleCache {
    /// Handle new.
    pub fn new(max: usize) -> Self {
        Self {
            max,
            entries: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Look up a module by hash. Moves the entry to the back (most
    /// recently used) so eviction drops the least recently used module.
    /// Fetch it.
    pub fn get(&self, hash: &str) -> Option<Arc<CachedModule>> {
        let mut entries = self.entries.lock().unwrap();
        let idx = entries.iter().position(|m| m.hash == hash)?;
        let module = entries.remove(idx);
        entries.push(module.clone());
        Some(module)
    }

    /// Handle PUT it.
    pub fn put(&self, module: Arc<CachedModule>) {
        let mut entries = self.entries.lock().unwrap();
        if let Some(idx) = entries.iter().position(|m| m.hash == module.hash) {
            entries.remove(idx);
        }
        if entries.len() >= self.max {
            entries.remove(0); // evict least recently used
        }
        entries.push(module);
    }

    /// Handle len.
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    /// Handle is_empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Forget a module by hash (used when a module is deleted).
    /// Remove it.
    pub fn remove(&self, hash: &str) {
        let mut entries = self.entries.lock().unwrap();
        if let Some(idx) = entries.iter().position(|m| m.hash == hash) {
            entries.remove(idx);
        }
    }
}

/// Callback config for proxy-back host functions (from the execute request).
///
/// `host_functions` maps each WASM-imported host-function name to the path
/// template on the calling service's internal API (e.g.
/// `ledger_get_balance` → `/accounts/{args.0}/balance`). Func resolves these
/// dynamically at execute time - it does **not** pre-register any
/// service-specific host functions.
#[derive(Debug, Clone, Deserialize, Serialize, Default, ToSchema)]
/// Configuration for callback.
pub struct CallbackConfig {
    /// The base URL.
    pub base_url: String,
    /// The auth token.
    pub auth_token: String,
    /// The internal path.
    pub internal_path: String,
    #[serde(default)]
    /// The host functions.
    pub host_functions: std::collections::HashMap<String, String>,
}

/// `POST /v1/modules/{id}/execute` request body.
#[derive(Debug, Clone, Deserialize, ToSchema)]
/// Request body for execute.
pub struct ExecuteRequest {
    /// The hook.
    pub hook: String,
    /// The context.
    pub context: serde_json::Value,
    #[serde(default)]
    /// The callback config.
    pub callback_config: Option<CallbackConfig>,
    /// Optional idempotency key (principles §4.14 - every trigger
    /// dedupes on the event's key): a replayed execution with the same
    /// key returns the cached response instead of re-running the hook.
    #[serde(default)]
    /// The idempotency key.
    pub idempotency_key: Option<String>,
}

/// `POST /v1/modules/{id}/execute` response body.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
/// Response payload for execute.
pub struct ExecuteResponse {
    /// The result.
    pub result: String,
    /// The reject reason.
    pub reject_reason: String,
    /// The directives.
    pub directives: serde_json::Value,
    /// The custom data.
    pub custom_data: serde_json::Value,
    /// The fuel used.
    pub fuel_used: u64,
    /// The duration ms.
    pub duration_ms: u64,
}

/// Known hook export names. Unknown hook names on upload are
/// rejected; execute only dispatches to these.
/// The known hooks constant.
pub const KNOWN_HOOKS: &[&str] = &[
    "pre_posting",
    "post_posting",
    "scheduled_event",
    "activation",
    "deactivation",
];

/// Built-in host-function names Func provides locally (no proxy-back).
/// Everything else must come from the `host_functions` map.
const BUILTIN_MODULE: &str = "env";
const BUILTINS: &[&str] = &[
    "malloc",
    "free",
    "log",
    "util_now",
    "util_date_add",
    "util_round",
];
/// Import namespaces rejected outright (WASI never allowed).
const WASI_MODULES: &[&str] = &["wasi_snapshot_preview1", "wasi", "wasi_unstable"];

/// Per-invocation host state.
struct HostState {
    log_lines: Vec<String>,
    memory_granted: u64,
    memory_max: usize,
}

impl HostState {
    fn new(memory_max: usize) -> Self {
        Self {
            log_lines: Vec::new(),
            memory_granted: 0,
            memory_max,
        }
    }
}

impl ResourceLimiter for HostState {
    fn memory_growing(
        &mut self,
        delta: usize,
        _current: usize,
        _max: Option<usize>,
    ) -> Result<bool, Error> {
        let next = self.memory_granted + delta as u64;
        if next > self.memory_max as u64 {
            return Ok(false); // exceed the cap → allocation fails
        }
        self.memory_granted = next;
        Ok(true)
    }

    fn table_growing(
        &mut self,
        _delta: u32,
        _current: u32,
        _max: Option<u32>,
    ) -> Result<bool, Error> {
        Ok(true)
    }
}

/// The runtime engine + config. Cheap to clone.
#[derive(Clone)]
/// The wasmruntime type.
pub struct WasmRuntime {
    /// The engine.
    pub engine: Engine,
    /// Maximum fuel.
    pub max_fuel: u64,
    /// Maximum memory bytes.
    pub max_memory_bytes: usize,
    /// The timeout ms.
    pub timeout_ms: u64,
    /// The cache.
    pub cache: Arc<ModuleCache>,
    http: reqwest::Client,
}

impl WasmRuntime {
    /// Handle new.
    pub fn new(
        max_fuel: u64,
        max_memory_bytes: usize,
        timeout_ms: u64,
        cache_max: usize,
    ) -> anyhow::Result<Self> {
        let mut cfg = Config::new();
        cfg.consume_fuel(true);
        // Epoch interruption powers the wall-clock deadline. Ticks are
        // generated by an interval task started once per process.
        cfg.epoch_interruption(true);
        cfg.async_support(true);
        let engine = Engine::new(&cfg)?;
        start_epoch_ticker(engine.clone(), timeout_ms);
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(2000))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Ok(Self {
            engine,
            max_fuel,
            max_memory_bytes,
            timeout_ms,
            cache: Arc::new(ModuleCache::new(cache_max)),
            http,
        })
    }

    /// SHA-256 hash of a WASM binary, formatted `sha256:hex…`.
    /// Handle wasm hash.
    pub fn wasm_hash(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        format!("sha256:{}", hex_encode(hasher.finalize()))
    }

    /// Parse a WASM binary and cache the compiled module.
    /// Handle compile and cache.
    pub fn compile_and_cache(
        &self,
        bytes: &[u8],
        hash: &str,
        hooks: Vec<String>,
    ) -> Result<Arc<CachedModule>, String> {
        if let Some(cached) = self.cache.get(hash) {
            return Ok(cached);
        }
        let module =
            Module::from_binary(&self.engine, bytes).map_err(|e| format!("wasm parse: {e}"))?;
        let cached = Arc::new(CachedModule {
            hash: hash.to_string(),
            module,
            hooks,
        });
        self.cache.put(cached.clone());
        Ok(cached)
    }

    /// Validate a WASM binary: parse, reject WASI imports, verify declared
    /// hooks are exported, and - when a `host_functions` map is available -
    /// verify every non-built-in import is covered by the map.
    /// Validate it.
    pub fn validate(
        &self,
        bytes: &[u8],
        declared_hooks: &[String],
        host_functions: Option<&std::collections::HashMap<String, String>>,
    ) -> Result<Vec<String>, String> {
        let module =
            Module::from_binary(&self.engine, bytes).map_err(|e| format!("wasm parse: {e}"))?;
        for imp in module.imports() {
            let module_name = imp.module();
            if WASI_MODULES.contains(&module_name) {
                return Err(format!(
                    "WASI imports are not allowed: {module_name}/{}",
                    imp.name()
                ));
            }
            if let Some(map) = host_functions {
                let name = imp.name();
                if module_name == BUILTIN_MODULE
                    && !BUILTINS.contains(&name)
                    && !map.contains_key(name)
                {
                    return Err(format!(
                        "import '{name}' is not a built-in and missing from host_functions map"
                    ));
                }
            }
        }
        let exports: Vec<String> = module.exports().map(|e| e.name().to_string()).collect();
        for hook in declared_hooks {
            if !exports.contains(hook) {
                return Err(format!("missing hook export: {hook}"));
            }
        }
        Ok(exports)
    }

    /// Execute a hook on a cached module.
    ///
    /// Protocol (SDK ABI): write `context` JSON at `(ptr, len)` obtained
    /// from the module's `malloc`, call the hook export `hook(ptr, len) ->
    /// resp_ptr`, read the response JSON from `resp_ptr`, free both.
    /// Execute it.
    pub async fn execute(
        &self,
        module: &CachedModule,
        req: &ExecuteRequest,
    ) -> Result<ExecuteResponse, String> {
        let start = std::time::Instant::now();
        let mut store = Store::new(&self.engine, HostState::new(self.max_memory_bytes));
        store.limiter(|state| state as &mut dyn ResourceLimiter);
        store
            .set_fuel(self.max_fuel)
            .map_err(|e| format!("set fuel: {e}"))?;
        // Epoch deadline: execution beyond `timeout_ms` is interrupted.
        store.set_epoch_deadline(1);

        let mut linker: Linker<HostState> = Linker::new(&self.engine);
        register_builtins_into(&mut linker);
        register_dynamic_imports(
            &mut linker,
            &module.module,
            req.callback_config.as_ref(),
            self.http.clone(),
        )
        .map_err(|e| format!("host fn registration: {e}"))?;

        let instance = linker
            .instantiate_async(&mut store, &module.module)
            .await
            .map_err(|e| format!("instantiate: {e}"))?;

        // Request JSON → module linear memory. The host allocates from its
        // own arena (same allocator the module's `malloc` import hands out);
        // the module reads the buffer via the (ptr, len) hook arguments.
        let request_json =
            serde_json::to_vec(&req.context).map_err(|e| format!("serialize context: {e}"))?;
        // Verify the hook export signature first - a missing hook is a
        // caller error, not a sandbox error, and must not be masked by the
        // memory check.
        if instance.get_export(&mut store, &req.hook).is_none() {
            return Err(format!(
                "hook '{}' not exported with signature (i32, i32) -> i32",
                req.hook
            ));
        }
        let mem = instance
            .get_memory(&mut store, "memory")
            .ok_or("module does not have a 'memory' export (required by the hook ABI)")?;
        let req_ptr = bump_malloc(request_json.len() as i32);
        if req_ptr <= 0 {
            return Err("host allocator returned non-positive pointer".into());
        }
        {
            let end = req_ptr as usize + request_json.len();
            // Grow linear memory to cover the arena offset when the module's
            // own memory declaration is smaller (the ResourceLimiter caps
            // total growth at max_memory_bytes).
            while (end as u64) > (mem.data_size(&store) as u64) {
                if mem.grow(&mut store, 1).is_err() {
                    return Err(format!(
                        "module memory too small for request (need {end}, have {})",
                        mem.data_size(&store)
                    ));
                }
            }
            mem.write(&mut store, req_ptr as usize, &request_json)
                .map_err(|e| format!("write request: {e}"))?;
        }

        // Call the hook export.
        let hook_func = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, &req.hook)
            .map_err(|_| {
                format!(
                    "hook '{}' not exported with signature (i32, i32) -> i32",
                    req.hook
                )
            })?;

        let call = hook_func.call_async(&mut store, (req_ptr, request_json.len() as i32));
        let resp_ptr =
            match tokio::time::timeout(std::time::Duration::from_millis(self.timeout_ms), call)
                .await
            {
                Ok(Ok(ptr)) => ptr,
                Ok(Err(e)) => {
                    // The trap Display only shows the wasm backtrace; the actual
                    // cause (out-of-fuel, epoch interrupt, memory fault) lives in
                    // the source chain.
                    let mut msg = e.to_string();
                    if let Some(cause) = e.source() {
                        msg.push_str(" | cause: ");
                        msg.push_str(&cause.to_string());
                    }
                    if msg.contains("fuel") {
                        return Err(format!("fuel exhausted: {msg}"));
                    }
                    if msg.contains("interrupted") || msg.contains("epoch") {
                        return Err(format!("execution timed out after {}ms", self.timeout_ms));
                    }
                    return Err(format!("hook execution failed: {msg}"));
                }
                Err(_) => {
                    return Err(format!(
                        "hook execution timed out after {}ms",
                        self.timeout_ms
                    ));
                }
            };

        // Read the response JSON from module memory.
        let mem = instance
            .get_memory(&mut store, "memory")
            .ok_or("module does not have a 'memory' export")?;
        let response_json = read_response_json(&mem, &store, resp_ptr)?;

        // Free the request + response buffers (best-effort).
        if let Ok(free_fn) = instance.get_typed_func::<i32, ()>(&mut store, "free") {
            let _ = free_fn.call_async(&mut store, req_ptr).await;
            let _ = free_fn.call_async(&mut store, resp_ptr).await;
        }

        // Parse the HookResponse envelope.
        let parsed: serde_json::Value =
            serde_json::from_slice(&response_json).map_err(|e| format!("response json: {e}"))?;
        let result = parsed
            .get("result")
            .and_then(|v| v.as_str())
            .unwrap_or("accept")
            .to_string();
        let reject_reason = parsed
            .get("reject_reason")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let directives = parsed
            .get("directives")
            .cloned()
            .unwrap_or(serde_json::Value::Array(vec![]));
        let custom_data = parsed
            .get("custom_data")
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        let fuel_remaining = store.get_fuel().unwrap_or(0);
        let fuel_used = self.max_fuel.saturating_sub(fuel_remaining);
        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(ExecuteResponse {
            result,
            reject_reason,
            directives,
            custom_data,
            fuel_used,
            duration_ms,
        })
    }

    /// Drop a module from the cache (post-delete).
    /// Handle evict.
    pub fn evict(&self, hash: &str) {
        self.cache.remove(hash);
    }
}

/// Read a JSON response value starting at `resp_ptr`. The SDK's
/// `write_response` does not communicate the length, so we locate the end of
/// the JSON value by brace/bracket-depth tracking (string-aware), capped at
/// 1 MiB.
fn read_response_json(
    mem: &Memory,
    store: &Store<HostState>,
    resp_ptr: i32,
) -> Result<Vec<u8>, String> {
    if resp_ptr <= 0 {
        return Err("module returned non-positive response pointer".into());
    }
    let data = mem.data(store);
    let start = resp_ptr as usize;
    if start >= data.len() {
        return Err("response pointer out of bounds".into());
    }
    let mut depth: i32 = 0;
    let mut in_string = false;
    let mut escaped = false;
    let mut seen_open = false;
    let mut end = None;
    for (i, b) in data[start..].iter().enumerate() {
        if i >= 1024 * 1024 {
            break; // 1 MiB cap
        }
        let c = *b as char;
        if in_string {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => in_string = true,
            '{' | '[' => {
                depth += 1;
                seen_open = true;
            }
            '}' | ']' => {
                depth -= 1;
                if depth == 0 && seen_open {
                    end = Some(i + 1);
                    break;
                }
            }
            _ => {}
        }
    }
    match end {
        Some(e) => Ok(data[start..start + e].to_vec()),
        None => Err("could not locate complete JSON response in module memory".into()),
    }
}

/// Register built-in host functions (computed locally, no proxy-back).
/// `malloc` and `free` are implemented in `execute` over the module's own
/// linear memory; the remaining built-ins (`log`, `util_*`) are wired in
/// `execute` directly onto the per-invocation Linker (see below).
fn register_builtins_into(linker: &mut Linker<HostState>) {
    linker
        .func_wrap(
            BUILTIN_MODULE,
            "malloc",
            |_caller: Caller<HostState>, size: i32| -> i32 { bump_malloc(size) },
        )
        .expect("link malloc");
    linker
        .func_wrap(
            BUILTIN_MODULE,
            "free",
            |_caller: Caller<HostState>, _ptr: i32| {},
        )
        .expect("link free");
    linker
        .func_wrap(
            BUILTIN_MODULE,
            "log",
            |mut caller: Caller<HostState>,
             level_ptr: i32,
             level_len: i32,
             msg_ptr: i32,
             msg_len: i32| {
                let (level, msg) =
                    read_two_strings(&mut caller, level_ptr, level_len, msg_ptr, msg_len);
                tracing::info!(target: "func::wasm", level = %level, message = %msg, "wasm log");
                caller.data_mut().log_lines.push(format!("{level}: {msg}"));
            },
        )
        .expect("link log");
    linker
        .func_wrap(
            BUILTIN_MODULE,
            "util_now",
            |_caller: Caller<HostState>| -> i64 { chrono::Utc::now().timestamp() },
        )
        .expect("link util_now");
    linker
        .func_wrap(
            BUILTIN_MODULE,
            "util_date_add",
            |_caller: Caller<HostState>, ts: i64, days: i32| -> i64 { ts + (days as i64) * 86_400 },
        )
        .expect("link util_date_add");
    linker
        .func_wrap(
            BUILTIN_MODULE,
            "util_round",
            |_caller: Caller<HostState>, amount: f64, precision: i32| -> f64 {
                let multiplier = 10f64.powi(precision.clamp(0, 18));
                (amount * multiplier).round() / multiplier
            },
        )
        .expect("link util_round");
}

/// Bump allocator over module linear memory: hands out sequential regions
/// anchored 1 MiB into linear memory (module heap data lives below that in
/// practice). Each allocation is 16-byte aligned. State is process-global -
/// acceptable because each invocation uses a fresh Store and allocations are
/// bounded (request buffer + module response buffer + proxy-back results).
fn bump_malloc(size: i32) -> i32 {
    use std::sync::atomic::{AtomicI32, Ordering};
    static ARENA: AtomicI32 = AtomicI32::new(1024 * 1024);
    if size <= 0 {
        return 0;
    }
    let aligned = (size + 15) & !15;
    ARENA.fetch_add(aligned, Ordering::SeqCst)
}

/// Caller-shaped wrapper for the module-facing `malloc` host function.
#[allow(dead_code)]
fn bump_malloc_caller(caller: &mut Caller<'_, HostState>, size: i32) -> i32 {
    let _ = caller.data_mut().memory_granted; // limiter tracks growth separately
    bump_malloc(size)
}

/// Read two (ptr,len) string pairs from module memory (for `log`).
fn read_two_strings(
    caller: &mut Caller<'_, HostState>,
    ptr1: i32,
    len1: i32,
    ptr2: i32,
    len2: i32,
) -> (String, String) {
    let mut read = |p: i32, l: i32| -> String {
        if p <= 0 || l <= 0 || l > 65536 {
            return String::new();
        }
        let Some(mem) = caller.get_export("memory") else {
            return String::new();
        };
        let Some(mem) = mem.into_memory() else {
            return String::new();
        };
        let data = mem.data(&caller);
        let start = p as usize;
        let end = start + l as usize;
        if end > data.len() {
            return String::new();
        }
        String::from_utf8_lossy(&data[start..end]).to_string()
    };
    (read(ptr1, len1), read(ptr2, len2))
}

/// Register one wasmtime host function per non-built-in WASM import, backed
/// by the proxy-back HTTP resolver. Every dynamic import has ABI
/// `(i32, i32) -> i32`: args are a pointer/length to a JSON array of
/// positional arguments; the return is a pointer to the response JSON.
fn register_dynamic_imports(
    linker: &mut Linker<HostState>,
    module: &Module,
    callback: Option<&CallbackConfig>,
    http: reqwest::Client,
) -> Result<(), String> {
    let self_engine = linker.engine().clone();
    let imports: Vec<(String, String)> = module
        .imports()
        .map(|i| (i.module().to_string(), i.name().to_string()))
        .filter(|(m, n)| m == BUILTIN_MODULE && !BUILTINS.contains(&n.as_str()))
        .collect();
    for (module_name, fn_name) in imports {
        let cb = match callback {
            Some(cb) => cb,
            None => {
                return Err(format!(
                    "module imports host function '{fn_name}' but the execute request has no callback_config"
                ));
            }
        };
        let path_template = match cb.host_functions.get(&fn_name) {
            Some(p) => p.clone(),
            None => {
                return Err(format!(
                    "module imports host function '{fn_name}' which is missing from callback_config.host_functions"
                ));
            }
        };
        let base_url = cb.base_url.trim_end_matches('/').to_string();
        let internal_path = cb.internal_path.trim_end_matches('/').to_string();
        let auth_token = cb.auth_token.clone();
        let http = http.clone();
        let ty = FuncType::new(
            &self_engine,
            vec![ValType::I32, ValType::I32],
            vec![ValType::I32],
        );
        let fn_name_cloned = fn_name.clone();
        linker
            .func_new_async(
                &module_name,
                &fn_name,
                ty,
                move |mut caller: Caller<'_, HostState>,
                      params: &'_ [Val],
                      results: &'_ mut [Val]| {
                    let http = http.clone();
                    let base_url = base_url.clone();
                    let internal_path = internal_path.clone();
                    let path_template = path_template.clone();
                    let auth_token = auth_token.clone();
                    let fn_name = fn_name_cloned.clone();
                    Box::new(async move {
                        if params.len() != 2 || results.is_empty() {
                            anyhow::bail!("dynamic host fn {fn_name}: bad ABI");
                        }
                        let args_ptr = val_i32(&params[0])?;
                        let args_len = val_i32(&params[1])?;
                        // Read the args JSON array from module memory.
                        let args: Vec<serde_json::Value> = {
                            let mem = caller
                                .get_export("memory")
                                .and_then(|e| e.into_memory())
                                .ok_or_else(|| {
                                    anyhow::anyhow!("no module memory for host fn args")
                                })?;
                            let data = mem.data(&caller);
                            let start = args_ptr.max(0) as usize;
                            let end = start + args_len.max(0) as usize;
                            if start > data.len() || end > data.len() {
                                anyhow::bail!("host fn args out of bounds");
                            }
                            serde_json::from_slice(&data[start..end]).unwrap_or_default()
                        };
                        let resolved = substitute_args(&path_template, &args)
                            .map_err(|e| anyhow::anyhow!("{e}"))?;
                        let url = format!("{base_url}{internal_path}{resolved}");
                        let resp = http
                            .get(&url)
                            .bearer_auth(&auth_token)
                            .send()
                            .await
                            .map_err(|e| anyhow::anyhow!("proxy-back {fn_name} failed: {e}"))?;
                        if !resp.status().is_success() {
                            anyhow::bail!("proxy-back {fn_name} returned {}", resp.status());
                        }
                        let bytes = resp
                            .bytes()
                            .await
                            .map_err(|e| anyhow::anyhow!("proxy-back {fn_name} body: {e}"))?;
                        if bytes.len() > 1024 * 1024 {
                            anyhow::bail!("proxy-back {fn_name} response exceeds 1 MiB cap");
                        }
                        let mem = caller
                            .get_export("memory")
                            .and_then(|e| e.into_memory())
                            .ok_or_else(|| {
                                anyhow::anyhow!("no module memory for host fn result")
                            })?;
                        let ptr = bump_malloc(bytes.len() as i32);
                        mem.write(&mut caller, ptr as usize, &bytes)
                            .map_err(|e| anyhow::anyhow!("write host fn result: {e}"))?;
                        results[0] = Val::I32(ptr);
                        Ok(())
                    })
                },
            )
            .map_err(|e| format!("link dynamic import {fn_name}: {e}"))?;
    }
    Ok(())
}

/// Substitute `{args.N}` placeholders in a path template with the WASM call
/// arguments (stringified, percent-encoded). Unknown placeholders are an
/// error.
/// Handle substitute args.
pub fn substitute_args(
    template: &str,
    args: &[serde_json::Value],
) -> Result<String, anyhow::Error> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find("{args.") {
        out.push_str(&rest[..open]);
        let after = &rest[open + 6..];
        let close = after
            .find('}')
            .ok_or_else(|| anyhow::anyhow!("unterminated placeholder in path template"))?;
        let idx: usize = after[..close]
            .parse()
            .map_err(|_| anyhow::anyhow!("bad args index in path template"))?;
        let val = args.get(idx).ok_or_else(|| {
            anyhow::anyhow!(
                "path template references args.{idx} but only {} args provided",
                args.len()
            )
        })?;
        match val {
            serde_json::Value::String(s) => out.push_str(&urlencode_path(s)),
            other => out.push_str(&other.to_string()),
        }
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Extract an i32 from a `Val` (the dynamic host-fn ABI is all-i32).
fn val_i32(v: &Val) -> Result<i32, Error> {
    match v {
        Val::I32(x) => Ok(*x),
        other => Err(anyhow::anyhow!("expected i32 argument, got {other:?}")),
    }
}

/// Percent-encode a path segment (conservative: encode everything except
/// unreserved characters).
fn urlencode_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// Background task ticking wasmtime epochs - powers the wall-clock deadline.
fn start_epoch_ticker(engine: Engine, timeout_ms: u64) {
    tokio::spawn(async move {
        // Tick ~10x per timeout period so interruption granularity is tight.
        let period = std::time::Duration::from_millis((timeout_ms / 10).max(10));
        let mut interval = tokio::time::interval(period);
        loop {
            interval.tick().await;
            engine.increment_epoch();
        }
    });
}

fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal runtime for cache tests (engine construction only).
    fn mk_runtime() -> WasmRuntime {
        sentin8::tls::crypto::sentin8_pq_provider()
            .install_default()
            .ok();
        WasmRuntime::new(10_000, 16 * 1024 * 1024, 5_000, 10).unwrap()
    }

    /// A trivial valid WASM module (empty, no imports/exports).
    fn mk_module(rt: &WasmRuntime) -> Module {
        // (module) - the smallest valid binary.
        let bytes: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        Module::from_binary(&rt.engine, bytes).unwrap()
    }

    #[test]
    fn substitute_args_basic() {
        let args = vec![serde_json::json!("acct-1"), serde_json::json!("flag")];
        let out = substitute_args("/accounts/{args.0}/flags/{args.1}", &args).unwrap();
        assert_eq!(out, "/accounts/acct-1/flags/flag");
    }

    #[test]
    fn substitute_args_urlencodes() {
        let args = vec![serde_json::json!("a b/c")];
        let out = substitute_args("/x/{args.0}", &args).unwrap();
        assert_eq!(out, "/x/a%20b%2Fc");
    }

    #[test]
    fn substitute_args_missing_index() {
        let out = substitute_args("/x/{args.3}", &[]);
        assert!(out.is_err());
    }

    #[test]
    fn substitute_args_non_string() {
        let args = vec![serde_json::json!(42)];
        let out = substitute_args("/n/{args.0}", &args).unwrap();
        assert_eq!(out, "/n/42");
    }

    #[tokio::test]
    async fn lru_cache_order() {
        let rt = mk_runtime();
        let cache = ModuleCache::new(2);
        let make = |h: &str| {
            Arc::new(CachedModule {
                hash: h.to_string(),
                module: mk_module(&rt),
                hooks: vec![],
            })
        };
        cache.put(make("a"));
        cache.put(make("b"));
        // Touch "a" so "b" becomes LRU.
        assert!(cache.get("a").is_some());
        cache.put(make("c"));
        // "b" should have been evicted, "a" and "c" remain.
        assert!(cache.get("a").is_some());
        assert!(cache.get("b").is_none());
        assert!(cache.get("c").is_some());
    }

    #[tokio::test]
    async fn cache_remove() {
        let rt = mk_runtime();
        let cache = ModuleCache::new(3);
        let m = Arc::new(CachedModule {
            hash: "h".into(),
            module: mk_module(&rt),
            hooks: vec![],
        });
        cache.put(m);
        assert_eq!(cache.len(), 1);
        cache.remove("h");
        assert_eq!(cache.len(), 0);
    }
}
