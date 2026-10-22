-- Explicit account linking: bind link flows to the signed-in user and session.
ALTER TABLE oauth_states ADD COLUMN link_user_id TEXT;
ALTER TABLE oauth_states ADD COLUMN link_session_id TEXT;

-- A provider identity can belong to exactly one user.
CREATE UNIQUE INDEX IF NOT EXISTS uq_oauth_accounts_provider_account ON oauth_accounts(provider, provider_account_id);
