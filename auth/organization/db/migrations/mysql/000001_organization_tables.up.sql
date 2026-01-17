-- Organization plugin tables

-- Organizations table
CREATE TABLE IF NOT EXISTS organizations (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL UNIQUE,
    logo LONGTEXT,
    metadata LONGTEXT,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Members table
CREATE TABLE IF NOT EXISTS members (
    id VARCHAR(255) PRIMARY KEY,
    organization_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'member',
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY unique_org_user (organization_id, user_id),
    INDEX idx_members_organization_id (organization_id),
    INDEX idx_members_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Invitations table
CREATE TABLE IF NOT EXISTS invitations (
    id VARCHAR(255) PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    organization_id VARCHAR(255) NOT NULL,
    inviter_id VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'member',
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    expires_at TIMESTAMP(6),
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    INDEX idx_invitations_organization_id (organization_id),
    INDEX idx_invitations_email (email),
    INDEX idx_invitations_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Teams table
CREATE TABLE IF NOT EXISTS teams (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    organization_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    INDEX idx_teams_organization_id (organization_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Team members table
CREATE TABLE IF NOT EXISTS team_members (
    id VARCHAR(255) PRIMARY KEY,
    team_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY unique_team_user (team_id, user_id),
    INDEX idx_team_members_team_id (team_id),
    INDEX idx_team_members_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
