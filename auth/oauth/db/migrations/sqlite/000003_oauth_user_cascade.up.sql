-- Delete OAuth data together with its user.
-- Rows left behind by users deleted before this migration can never be used again
-- (signing in with such an identity failed), so remove them first.
-- SQLite cannot add a foreign key to an existing table, so both tables are rebuilt
-- (same columns in the same order). Like the core tables' foreign keys, the cascade
-- needs foreign key enforcement enabled on the connection (e.g. ?_foreign_keys=on).
DELETE FROM oauth_accounts WHERE user_id NOT IN (SELECT id FROM users);
DELETE FROM oauth_states WHERE link_user_id IS NOT NULL AND link_user_id NOT IN (SELECT id FROM users);

CREATE TABLE oauth_accounts_new (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    provider_account_id TEXT NOT NULL,
    access_token TEXT,
    refresh_token TEXT,
    access_token_expires_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
INSERT INTO oauth_accounts_new (id, user_id, provider, provider_account_id, access_token, refresh_token, access_token_expires_at, created_at, updated_at)
    SELECT id, user_id, provider, provider_account_id, access_token, refresh_token, access_token_expires_at, created_at, updated_at FROM oauth_accounts;
DROP TABLE oauth_accounts;
ALTER TABLE oauth_accounts_new RENAME TO oauth_accounts;
CREATE INDEX IF NOT EXISTS idx_oauth_accounts_user_id ON oauth_accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_accounts_provider ON oauth_accounts(provider, provider_account_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_oauth_accounts_provider_account ON oauth_accounts(provider, provider_account_id);

CREATE TABLE oauth_states_new (
    state TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    verifier TEXT,
    redirect_to TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    link_user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    link_session_id TEXT
);
INSERT INTO oauth_states_new (state, provider, verifier, redirect_to, created_at, expires_at, link_user_id, link_session_id)
    SELECT state, provider, verifier, redirect_to, created_at, expires_at, link_user_id, link_session_id FROM oauth_states;
DROP TABLE oauth_states;
ALTER TABLE oauth_states_new RENAME TO oauth_states;
CREATE INDEX IF NOT EXISTS idx_oauth_states_expires_at ON oauth_states(expires_at);
