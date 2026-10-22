ALTER TABLE oauth_states DROP CONSTRAINT IF EXISTS fk_oauth_states_link_user;
ALTER TABLE oauth_accounts DROP CONSTRAINT IF EXISTS fk_oauth_accounts_user;
