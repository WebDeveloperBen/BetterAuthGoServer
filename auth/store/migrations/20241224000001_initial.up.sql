-- Core Auth Tables
-- OAuth-specific tables (oauth_states, oauth_accounts) are managed by the OAuth plugin.

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    name VARCHAR(100) NOT NULL,
    image VARCHAR(500),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

--bun:split

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

--bun:split

-- Accounts table (email/password authentication)
-- For OAuth providers, see the oauth plugin's oauth_accounts table.
CREATE TABLE IF NOT EXISTS accounts (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    provider_account_id VARCHAR(255),
    password_hash VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

--bun:split

CREATE INDEX IF NOT EXISTS idx_accounts_user_id ON accounts(user_id);

--bun:split

CREATE INDEX IF NOT EXISTS idx_accounts_provider ON accounts(provider, provider_account_id);

--bun:split

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    last_used TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

--bun:split

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);

--bun:split

CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);

--bun:split

CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

--bun:split

-- Verifications table (email verification, password reset, etc.)
CREATE TABLE IF NOT EXISTS verifications (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    type VARCHAR(50) NOT NULL,
    identifier VARCHAR(255),
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

--bun:split

CREATE INDEX IF NOT EXISTS idx_verifications_token_hash ON verifications(token_hash);

--bun:split

CREATE INDEX IF NOT EXISTS idx_verifications_user_id_type ON verifications(user_id, type);
