-- Device codes table for OAuth 2.0 Device Authorization Grant (RFC 8628)
CREATE TABLE IF NOT EXISTS device_codes (
    id TEXT PRIMARY KEY,
    device_code TEXT NOT NULL,
    device_code_hash TEXT NOT NULL,
    user_code TEXT NOT NULL UNIQUE,
    client_id TEXT,
    scope TEXT,
    user_id TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    polling_interval INTEGER NOT NULL DEFAULT 5,
    last_polled_at TEXT,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Indexes for efficient lookups
CREATE INDEX IF NOT EXISTS idx_device_codes_device_code_hash ON device_codes(device_code_hash);
CREATE INDEX IF NOT EXISTS idx_device_codes_expires_at ON device_codes(expires_at);
