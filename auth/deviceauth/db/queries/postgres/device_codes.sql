-- name: CreateDeviceCode :exec
INSERT INTO device_codes (
    id, device_code, device_code_hash, user_code, client_id, scope,
    user_id, status, polling_interval, last_polled_at, expires_at, created_at, updated_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
);

-- name: GetDeviceCodeByUserCode :one
SELECT * FROM device_codes
WHERE REPLACE(user_code, '-', '') = REPLACE($1, '-', '')
LIMIT 1;

-- name: GetDeviceCodeByHash :one
SELECT * FROM device_codes
WHERE device_code_hash = $1 AND device_code = $2
LIMIT 1;

-- name: UpdateDeviceCodeStatus :exec
UPDATE device_codes
SET status = $2, user_id = $3, updated_at = $4
WHERE id = $1;

-- name: UpdateDeviceCodeLastPolled :exec
UPDATE device_codes
SET last_polled_at = $2, updated_at = $3
WHERE id = $1;

-- name: DeleteExpiredDeviceCodes :execrows
DELETE FROM device_codes
WHERE expires_at < NOW();

-- name: DeleteDeviceCode :exec
DELETE FROM device_codes
WHERE id = $1;
