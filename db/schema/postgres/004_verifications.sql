-- Verifications table (email verification, password reset tokens)
CREATE TABLE IF NOT EXISTS verifications (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL,
    identifier TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_verifications_token_hash ON verifications(token_hash);
CREATE INDEX IF NOT EXISTS idx_verifications_user_id_type ON verifications(user_id, type);
CREATE INDEX IF NOT EXISTS idx_verifications_expires_at ON verifications(expires_at);
