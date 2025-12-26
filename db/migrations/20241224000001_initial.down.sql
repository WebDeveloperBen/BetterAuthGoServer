-- Core Auth Tables - down migration
-- OAuth-specific tables are managed by the OAuth plugin.

DROP TABLE IF EXISTS verifications;

--bun:split

DROP TABLE IF EXISTS sessions;

--bun:split

DROP TABLE IF EXISTS accounts;

--bun:split

DROP TABLE IF EXISTS users;
