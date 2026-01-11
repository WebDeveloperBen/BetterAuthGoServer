-- APIKey plugin tables

-- API keys table
CREATE TABLE IF NOT EXISTS api_keys (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255),
    start VARCHAR(255) NOT NULL,
    prefix VARCHAR(255),
    `key` LONGTEXT NOT NULL,
    key_prefix VARCHAR(255) NOT NULL,
    user_id VARCHAR(255) NOT NULL,

    -- Rate limiting
    rate_limit_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    rate_limit_time_window BIGINT,
    rate_limit_max INTEGER,
    request_count INTEGER NOT NULL DEFAULT 0,

    -- Usage quota
    remaining INTEGER,
    refill_interval BIGINT,
    refill_amount INTEGER,
    last_refill_at TIMESTAMP(6),

    -- Status
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_request TIMESTAMP(6),
    expires_at TIMESTAMP(6),

    -- Metadata & permissions (JSON strings)
    permissions LONGTEXT,
    metadata LONGTEXT,

    -- Timestamps
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_prefix ON api_keys(key_prefix);
CREATE INDEX IF NOT EXISTS idx_api_keys_enabled ON api_keys(enabled);