-- Explicit account linking: bind link flows to the signed-in user and session.
ALTER TABLE oauth_states
    ADD COLUMN link_user_id VARCHAR(255) NULL,
    ADD COLUMN link_session_id VARCHAR(255) NULL;

-- A provider identity can belong to exactly one user.
CREATE UNIQUE INDEX uq_oauth_accounts_provider_account ON oauth_accounts(provider, provider_account_id);
