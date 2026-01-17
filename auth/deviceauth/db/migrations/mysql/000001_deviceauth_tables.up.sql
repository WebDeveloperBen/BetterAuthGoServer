-- DeviceAuth plugin tables

-- Device codes for OAuth 2.0 Device Authorization Grant
CREATE TABLE IF NOT EXISTS device_codes (
    id VARCHAR(255) PRIMARY KEY,
    device_code VARCHAR(255) NOT NULL,
    device_code_hash VARCHAR(255) NOT NULL,
    user_code VARCHAR(255) NOT NULL,
    client_id VARCHAR(255),
    scope LONGTEXT,
    user_id VARCHAR(255),
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    polling_interval INTEGER NOT NULL DEFAULT 5,
    last_polled_at TIMESTAMP(6),
    expires_at TIMESTAMP(6) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    INDEX idx_device_codes_user_code (user_code),
    INDEX idx_device_codes_device_code_hash (device_code_hash),
    INDEX idx_device_codes_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
