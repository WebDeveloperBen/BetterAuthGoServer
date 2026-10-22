-- Rollback explicit account linking
DROP INDEX IF EXISTS uq_oauth_accounts_provider_account;

ALTER TABLE oauth_states
    DROP COLUMN IF EXISTS link_session_id,
    DROP COLUMN IF EXISTS link_user_id;
