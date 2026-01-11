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
    rate_limit_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    rate_limit_time_window BIGINT,
    rate_limit_max INTEGER,
    request_count INTEGER NOT NULL DEFAULT 0,

    -- Usage quota
    remaining INTEGER,
    refill_interval BIGINT,
    refill_amount INTEGER,
    last_refill_at TIMESTAMPTZ,

    -- Status
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_request TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,

    -- Metadata & permissions (JSON strings)
    permissions TEXT,
    metadata TEXT,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_prefix ON api_keys(key_prefix);
CREATE INDEX IF NOT EXISTS idx_api_keys_enabled ON api_keys(enabled);
