-- OTP plugin tables

-- OTP tokens table (password reset, email verification)
CREATE TABLE IF NOT EXISTS otp_tokens (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    identifier VARCHAR(255),
    expires_at TIMESTAMP(6) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    INDEX idx_otp_tokens_token_hash (token_hash),
    INDEX idx_otp_tokens_user_type (user_id, type),
    INDEX idx_otp_tokens_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
