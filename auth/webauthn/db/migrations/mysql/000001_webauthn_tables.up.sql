-- WebAuthn plugin tables

-- WebAuthn credentials table (passkeys/security keys)
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    credential_id LONGBLOB NOT NULL,
    public_key LONGBLOB NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    transports LONGTEXT,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_used_at TIMESTAMP(6),
    INDEX idx_webauthn_credentials_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- WebAuthn sessions table (registration/login ceremony state)
CREATE TABLE IF NOT EXISTS webauthn_sessions (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255),
    type VARCHAR(50) NOT NULL,
    data LONGBLOB NOT NULL,
    expires_at TIMESTAMP(6) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL,
    INDEX idx_webauthn_sessions_expires_at (expires_at),
    INDEX idx_webauthn_sessions_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
