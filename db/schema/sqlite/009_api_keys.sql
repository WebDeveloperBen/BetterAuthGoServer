-- API keys table
CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    name TEXT,
    start TEXT NOT NULL,
    prefix TEXT,
    key TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    user_id TEXT NOT NULL,

    -- Rate limiting
    rate_limit_enabled INTEGER NOT NULL DEFAULT 1,
    rate_limit_time_window INTEGER,
    rate_limit_max INTEGER,
    request_count INTEGER NOT NULL DEFAULT 0,

    -- Usage quota
    remaining INTEGER,
    refill_interval INTEGER,
    refill_amount INTEGER,
    last_refill_at TEXT,

    -- Status
    enabled INTEGER NOT NULL DEFAULT 1,
    last_request TEXT,
    expires_at TEXT,

    -- Metadata & permissions (JSON strings)
    permissions TEXT,
    metadata TEXT,

    -- Timestamps
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_prefix ON api_keys(key_prefix);
CREATE INDEX IF NOT EXISTS idx_api_keys_enabled ON api_keys(enabled);
