-- Remove admin and ban columns from users table
DROP INDEX IF EXISTS idx_users_role;

--bun:split

DROP INDEX IF EXISTS idx_users_banned;

--bun:split

ALTER TABLE users DROP COLUMN IF EXISTS role;

--bun:split

ALTER TABLE users DROP COLUMN IF EXISTS ban_reason;

--bun:split

ALTER TABLE users DROP COLUMN IF EXISTS banned_at;

--bun:split

ALTER TABLE users DROP COLUMN IF EXISTS banned;
