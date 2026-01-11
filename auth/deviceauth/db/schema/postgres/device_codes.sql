-- Device codes for OAuth 2.0 Device Authorization Grant
CREATE TABLE IF NOT EXISTS device_codes (
    id TEXT PRIMARY KEY,
    device_code TEXT NOT NULL,
    device_code_hash TEXT NOT NULL,
    user_code TEXT NOT NULL,
    client_id TEXT,
    scope TEXT,
    user_id TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    polling_interval INTEGER NOT NULL DEFAULT 5,
    last_polled_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_device_codes_user_code ON device_codes(user_code);
CREATE INDEX IF NOT EXISTS idx_device_codes_device_code_hash ON device_codes(device_code_hash);
CREATE INDEX IF NOT EXISTS idx_device_codes_expires_at ON device_codes(expires_at);
