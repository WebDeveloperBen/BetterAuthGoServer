-- OAuth states table (CSRF protection for OAuth flow)
CREATE TABLE IF NOT EXISTS oauth_states (
  state VARCHAR(255) PRIMARY KEY,
  provider VARCHAR(50) NOT NULL,
  verifier LONGTEXT,
  redirect_to LONGTEXT,
  created_at TIMESTAMP(6) NOT NULL,
  expires_at TIMESTAMP(6) NOT NULL,
  -- Set only for explicit account-linking flows: the signed-in user and session that started the flow.
  link_user_id VARCHAR(255),
  link_session_id VARCHAR(255),
  CONSTRAINT fk_oauth_states_link_user FOREIGN KEY (link_user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE INDEX IF NOT EXISTS idx_oauth_states_expires_at ON oauth_states (expires_at);

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
  CONSTRAINT fk_oauth_accounts_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE INDEX IF NOT EXISTS idx_oauth_accounts_user_id ON oauth_accounts (user_id);

CREATE INDEX IF NOT EXISTS idx_oauth_accounts_provider ON oauth_accounts (provider, provider_account_id);

-- A provider identity can belong to exactly one user.
CREATE UNIQUE INDEX uq_oauth_accounts_provider_account ON oauth_accounts (provider, provider_account_id);