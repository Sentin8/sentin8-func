-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Func
-- SPDX-License-Identifier: Apache-2.0

-- Sentin8:Func - WASM module registry.
-- Sentin8:Func is the generic, standalone WASM execution service. Any service
-- (Bank8:Ledger, Bank8:Payments, Sentin8:App, Bank8:FDX, …) uses it through the generic `func.modules`
-- table - Sentin8:Func owns no service-specific tables.
--
-- This file contains:
--   * func.modules
-- The Bank8:Ledger-owned bank8_ledger_product_versions (WASM binary metadata for Bank8:Ledger
-- product versions) and bank8_ledger_account_flags (set_flag directive) live in
-- the Bank8:Ledger SQL - they are Bank8:Ledger concepts, not Sentin8:Func concepts.

-- Sentin8:Func standalone module registry - WASM module metadata.
-- WASM binaries themselves are stored in Sentin8:Storage (object storage); this table
-- holds the hash, size, language, hooks, parameters, and status.
CREATE SCHEMA IF NOT EXISTS func;
CREATE TABLE IF NOT EXISTS func.modules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain          TEXT NOT NULL,                       -- 'ledger', 'payments', etc.
    product_id      TEXT NOT NULL,                        -- domain-specific identifier
    version_label   TEXT NOT NULL,
    wasm_hash       TEXT NOT NULL,                        -- sha256:hex…
    wasm_size       INTEGER NOT NULL,                     -- bytes
    wasm_language   TEXT NOT NULL CHECK (wasm_language IN ('typescript', 'rust')),
    hooks           TEXT[] NOT NULL DEFAULT '{}',         -- ["pre_posting","post_posting",…]
    parameters      JSONB NOT NULL DEFAULT '{}',
    description     TEXT,
    status          TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'active', 'deprecated')),
    sentin8_storage_object_key TEXT,                                -- Sentin8:Storage object key: func/{domain}/{id}.wasm
    uploaded_by     TEXT,
    env_id  UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (domain, product_id, version_label, env_id)
);

-- Only one active version per (domain, product_id) per environment
CREATE UNIQUE INDEX IF NOT EXISTS func_modules_active_idx
    ON func.modules (domain, product_id, env_id)
    WHERE status = 'active';

CREATE INDEX IF NOT EXISTS idx_func_modules_env ON func.modules (env_id);
CREATE INDEX IF NOT EXISTS idx_func_modules_domain_product ON func.modules (domain, product_id);

-- Enable RLS
ALTER TABLE func.modules ENABLE ROW LEVEL SECURITY;
ALTER TABLE func.modules FORCE ROW LEVEL SECURITY;

-- RLS policies
DROP POLICY IF EXISTS func_modules_select ON func.modules;
CREATE POLICY func_modules_select ON func.modules
    FOR SELECT USING (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS func_modules_insert ON func.modules;
CREATE POLICY func_modules_insert ON func.modules
    FOR INSERT WITH CHECK (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS func_modules_update ON func.modules;
CREATE POLICY func_modules_update ON func.modules
    FOR UPDATE USING (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS func_modules_delete ON func.modules;
CREATE POLICY func_modules_delete ON func.modules
    FOR DELETE USING (sentin8_current_env_id() = env_id);

-- ── Grants ──

-- sentin8_func_service: DML on all func tables.
GRANT SELECT, INSERT, UPDATE, DELETE ON func.modules TO sentin8_func_service;


-- ── Local outbox (DBX, architecture-principles §6.7) ─────────────────────
-- Producer path: func.outbox rows commit in the SAME transaction as the
-- domain change; a post-commit relay pushes them to Bus POST /v1/produce.
-- Generated from sentin8-outbox::outbox_table_sql("func").
CREATE TABLE IF NOT EXISTS func.outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    event_type      TEXT NOT NULL,
    stream_family   TEXT NOT NULL,
    payload         JSONB NOT NULL,
    publisher_id_token  TEXT,
    publisher_subject   TEXT,
    relayed         BOOLEAN NOT NULL DEFAULT false,
    relayed_at      TIMESTAMPTZ,
    relay_attempts  INT NOT NULL DEFAULT 0,
    next_retry_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_func_outbox_unrelayed
    ON func.outbox (created_at) WHERE relayed = false;
ALTER TABLE func.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE func.outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS outbox_select ON func.outbox;
CREATE POLICY outbox_select ON func.outbox FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_insert ON func.outbox;
CREATE POLICY outbox_insert ON func.outbox FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_update ON func.outbox;
CREATE POLICY outbox_update ON func.outbox FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
CREATE OR REPLACE FUNCTION func.func_notify_outbox() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    PERFORM pg_notify('func_outbox_changed', '');
    RETURN NEW;
END;
$fn$;
DROP TRIGGER IF EXISTS outbox_notify_trigger ON func.outbox;
CREATE TRIGGER outbox_notify_trigger
    AFTER INSERT ON func.outbox
    FOR EACH ROW
    EXECUTE FUNCTION func.func_notify_outbox();


-- ── Local audit journal (DBX §6.8) ────────────────────────────────────────
-- Spill journal for the canonical audit push: rows written same-tx as the
-- domain change, pushed to Sys POST /v1/audit (sentin8:sys:audit:write), then
-- marked pushed. A Sys outage never drops audit. Generated from
-- sentin8-audit::audit_journal_sql("func").
CREATE TABLE IF NOT EXISTS func.audit_journal (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    action          TEXT NOT NULL,
    target_resource_type TEXT,
    target_resource_id    TEXT,
    actor_user_id   TEXT,
    actor_subject_type TEXT,
    severity        TEXT NOT NULL DEFAULT 'info',
    correlation_id  TEXT,
    before_state    JSONB,
    after_state     JSONB,
    details         JSONB,
    pushed          BOOLEAN NOT NULL DEFAULT false,
    pushed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_func_audit_journal_unpushed
    ON func.audit_journal (created_at) WHERE pushed = false;
ALTER TABLE func.audit_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE func.audit_journal FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_journal_dml ON func.audit_journal;
CREATE POLICY audit_journal_dml ON func.audit_journal
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

-- Execute idempotency (func DESIGN §6, principles §4.14): every trigger
-- dedupes on the event's idempotency key. A replayed execute with the same
-- (module_id, hook, idempotency_key) returns the cached response instead of
-- re-running the hook. Rows expire after the TTL window (pruned by the
-- maintenance pass); a NULL idempotency_key never dedupes.
CREATE TABLE IF NOT EXISTS func.execute_dedupe (
    module_id       UUID NOT NULL,
    hook            TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    response        JSONB NOT NULL,
    env_id          UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (module_id, hook, idempotency_key)
);
ALTER TABLE func.execute_dedupe ENABLE ROW LEVEL SECURITY;
ALTER TABLE func.execute_dedupe FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS execute_dedupe_dml ON func.execute_dedupe;
CREATE POLICY execute_dedupe_dml ON func.execute_dedupe
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON func.execute_dedupe TO sentin8_func_service;


-- ── Schema grants (service-owned - the 2026-10-03 ownership pass) ─────
-- This service's own schema: USAGE for its role (platform.sql no longer
-- seeds per-service USAGE; the service declares it here).
GRANT USAGE ON SCHEMA func TO sentin8_func_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON func.outbox TO sentin8_func_service;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA func TO sentin8_func_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON func.audit_journal TO sentin8_func_service;
