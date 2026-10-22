-- Rollback explicit account linking
DROP INDEX IF EXISTS uq_oauth_accounts_provider_account;
ALTER TABLE oauth_states DROP COLUMN link_session_id;
ALTER TABLE oauth_states DROP COLUMN link_user_id;
