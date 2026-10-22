-- Rollback explicit account linking
DROP INDEX uq_oauth_accounts_provider_account ON oauth_accounts;

ALTER TABLE oauth_states
    DROP COLUMN link_session_id,
    DROP COLUMN link_user_id;
