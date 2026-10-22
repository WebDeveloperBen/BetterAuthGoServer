-- Delete OAuth data together with its user.
-- Rows left behind by users deleted before this migration can never be used again
-- (signing in with such an identity failed), so remove them before adding the keys.
DELETE FROM oauth_accounts WHERE user_id NOT IN (SELECT id FROM users);
DELETE FROM oauth_states WHERE link_user_id IS NOT NULL AND link_user_id NOT IN (SELECT id FROM users);

ALTER TABLE oauth_accounts
    ADD CONSTRAINT fk_oauth_accounts_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE oauth_states
    ADD CONSTRAINT fk_oauth_states_link_user FOREIGN KEY (link_user_id) REFERENCES users(id) ON DELETE CASCADE;
