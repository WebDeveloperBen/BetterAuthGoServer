-- Add admin and ban columns to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS banned BOOLEAN NOT NULL DEFAULT FALSE;

--bun:split

ALTER TABLE users ADD COLUMN IF NOT EXISTS banned_at TIMESTAMP;

--bun:split

ALTER TABLE users ADD COLUMN IF NOT EXISTS ban_reason VARCHAR(500);

--bun:split

ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(50) NOT NULL DEFAULT 'user';

--bun:split

CREATE INDEX IF NOT EXISTS idx_users_banned ON users(banned);

--bun:split

CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
