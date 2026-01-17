-- JWT revoked tokens table (token blocklist)
CREATE TABLE IF NOT EXISTS jwt_revoked_tokens (
    id TEXT PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_jwt_revoked_tokens_expires_at ON jwt_revoked_tokens(expires_at);

-- JWT keys table (for database-backed asymmetric keys)
CREATE TABLE IF NOT EXISTS jwt_keys (
    id TEXT PRIMARY KEY,
    algorithm TEXT NOT NULL,
    use TEXT NOT NULL,
    kty TEXT NOT NULL,
    status TEXT NOT NULL,
    private_key_enc TEXT NOT NULL,
    public_key_jwk TEXT NOT NULL,
    activated_at TIMESTAMPTZ NOT NULL,
    rotated_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_jwt_keys_algorithm_status ON jwt_keys(algorithm, status);
CREATE INDEX IF NOT EXISTS idx_jwt_keys_expires_at ON jwt_keys(expires_at);
