-- Rollback Organization plugin tables
-- Drop in reverse order due to foreign key constraints

DROP TABLE IF EXISTS team_members;
DROP TABLE IF EXISTS teams;
DROP TABLE IF EXISTS invitations;
DROP TABLE IF EXISTS members;
DROP TABLE IF EXISTS organizations;