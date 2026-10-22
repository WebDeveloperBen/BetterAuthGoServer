-- OAuth states table (CSRF protection for OAuth flow)
CREATE TABLE IF NOT EXISTS oauth_states (
  state TEXT PRIMARY KEY,
  provider TEXT NOT NULL,
  verifier TEXT,
  redirect_to TEXT,
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  -- Set only for explicit account-linking flows: the signed-in user and session that started the flow.
  link_user_id TEXT REFERENCES users (id) ON DELETE CASCADE,
  link_session_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_oauth_states_expires_at ON oauth_states (expires_at);

-- OAuth accounts table (linked OAuth provider accounts)
CREATE TABLE IF NOT EXISTS oauth_accounts (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  provider_account_id TEXT NOT NULL,
  access_token TEXT,
  refresh_token TEXT,
  access_token_expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_oauth_accounts_user_id ON oauth_accounts (user_id);

CREATE INDEX IF NOT EXISTS idx_oauth_accounts_provider ON oauth_accounts (provider, provider_account_id);

-- A provider identity can belong to exactly one user.
CREATE UNIQUE INDEX IF NOT EXISTS uq_oauth_accounts_provider_account ON oauth_accounts (provider, provider_account_id);

CREATE INDEX if NOT EXISTS idx ON oauth_accounts (user_id);
