-- Rebuild the OAuth tables without the user foreign keys.
CREATE TABLE oauth_accounts_old (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_account_id TEXT NOT NULL,
    access_token TEXT,
    refresh_token TEXT,
    access_token_expires_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
INSERT INTO oauth_accounts_old (id, user_id, provider, provider_account_id, access_token, refresh_token, access_token_expires_at, created_at, updated_at)
    SELECT id, user_id, provider, provider_account_id, access_token, refresh_token, access_token_expires_at, created_at, updated_at FROM oauth_accounts;
DROP TABLE oauth_accounts;
ALTER TABLE oauth_accounts_old RENAME TO oauth_accounts;
CREATE INDEX IF NOT EXISTS idx_oauth_accounts_user_id ON oauth_accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_accounts_provider ON oauth_accounts(provider, provider_account_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_oauth_accounts_provider_account ON oauth_accounts(provider, provider_account_id);

CREATE TABLE oauth_states_old (
    state TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    verifier TEXT,
    redirect_to TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    link_user_id TEXT,
    link_session_id TEXT
);
INSERT INTO oauth_states_old (state, provider, verifier, redirect_to, created_at, expires_at, link_user_id, link_session_id)
    SELECT state, provider, verifier, redirect_to, created_at, expires_at, link_user_id, link_session_id FROM oauth_states;
DROP TABLE oauth_states;
ALTER TABLE oauth_states_old RENAME TO oauth_states;
CREATE INDEX IF NOT EXISTS idx_oauth_states_expires_at ON oauth_states(expires_at);
