-- name: CreateDeviceCode :exec
INSERT INTO device_codes (
    id, device_code, device_code_hash, user_code, client_id, scope,
    user_id, status, polling_interval, last_polled_at, expires_at, created_at, updated_at
) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
);

-- name: GetDeviceCodeByUserCode :one
SELECT * FROM device_codes
WHERE REPLACE(user_code, '-', '') = REPLACE(?, '-', '')
LIMIT 1;

-- name: GetDeviceCodeByHash :one
SELECT * FROM device_codes
WHERE device_code_hash = ? AND device_code = ?
LIMIT 1;

-- name: UpdateDeviceCodeStatus :exec
UPDATE device_codes
SET status = ?, user_id = ?, updated_at = ?
WHERE id = ?;

-- name: UpdateDeviceCodeLastPolled :exec
UPDATE device_codes
SET last_polled_at = ?, updated_at = ?
WHERE id = ?;

-- name: DeleteExpiredDeviceCodes :execrows
DELETE FROM device_codes
WHERE expires_at < NOW(6);

-- name: DeleteDeviceCode :exec
DELETE FROM device_codes
WHERE id = ?;