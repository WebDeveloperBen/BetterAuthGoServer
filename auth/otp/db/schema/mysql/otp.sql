-- OTP tokens table (password reset, email verification)
CREATE TABLE IF NOT EXISTS otp_tokens (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    identifier VARCHAR(255),
    expires_at TIMESTAMP(6) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE INDEX IF NOT EXISTS idx_otp_tokens_token_hash ON otp_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_otp_tokens_user_type ON otp_tokens(user_id, type);
CREATE INDEX IF NOT EXISTS idx_otp_tokens_expires_at ON otp_tokens(expires_at);