-- OTP plugin tables for BetterAuth

-- OTP tokens table (password reset, email verification)
CREATE TABLE IF NOT EXISTS otp_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    type TEXT NOT NULL,
    identifier TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_otp_tokens_token_hash ON otp_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_otp_tokens_user_type ON otp_tokens(user_id, type);
CREATE INDEX IF NOT EXISTS idx_otp_tokens_expires_at ON otp_tokens(expires_at);
