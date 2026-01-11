-- Rollback core authentication tables
-- Drop in reverse order due to foreign key constraints

DROP TABLE IF EXISTS verifications;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS accounts;
DROP TABLE IF EXISTS users;