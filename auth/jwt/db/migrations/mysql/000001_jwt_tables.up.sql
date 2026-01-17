-- JWT plugin tables

-- JWT revoked tokens table (token blocklist)
CREATE TABLE IF NOT EXISTS jwt_revoked_tokens (
    id VARCHAR(255) PRIMARY KEY,
    expires_at TIMESTAMP(6) NOT NULL,
    revoked_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    INDEX idx_jwt_revoked_tokens_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- JWT keys table (for database-backed asymmetric keys)
CREATE TABLE IF NOT EXISTS jwt_keys (
    id VARCHAR(255) PRIMARY KEY,
    algorithm VARCHAR(50) NOT NULL,
    `use` VARCHAR(20) NOT NULL,
    kty VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL,
    private_key_enc LONGTEXT NOT NULL,
    public_key_jwk LONGTEXT NOT NULL,
    activated_at TIMESTAMP(6) NOT NULL,
    rotated_at TIMESTAMP(6),
    expires_at TIMESTAMP(6),
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    INDEX idx_jwt_keys_algorithm_status (algorithm, status),
    INDEX idx_jwt_keys_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
