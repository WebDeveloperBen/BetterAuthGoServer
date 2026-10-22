-- Explicit account linking: bind link flows to the signed-in user and session.
ALTER TABLE oauth_states
    ADD COLUMN IF NOT EXISTS link_user_id TEXT,
    ADD COLUMN IF NOT EXISTS link_session_id TEXT;

-- A provider identity can belong to exactly one user.
CREATE UNIQUE INDEX IF NOT EXISTS uq_oauth_accounts_provider_account ON oauth_accounts(provider, provider_account_id);
