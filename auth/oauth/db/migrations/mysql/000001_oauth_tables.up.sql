-- OAuth plugin tables

-- OAuth states table (CSRF protection for OAuth flow)
CREATE TABLE IF NOT EXISTS oauth_states (
    state VARCHAR(255) PRIMARY KEY,
    provider VARCHAR(50) NOT NULL,
    verifier LONGTEXT,
    redirect_to LONGTEXT,
    created_at TIMESTAMP(6) NOT NULL,
    expires_at TIMESTAMP(6) NOT NULL,
    INDEX idx_oauth_states_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- OAuth accounts table (linked OAuth provider accounts)
CREATE TABLE IF NOT EXISTS oauth_accounts (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    provider_account_id VARCHAR(255) NOT NULL,
    access_token LONGTEXT,
    refresh_token LONGTEXT,
    access_token_expires_at TIMESTAMP(6),
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    INDEX idx_oauth_accounts_user_id (user_id),
    INDEX idx_oauth_accounts_provider (provider, provider_account_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
