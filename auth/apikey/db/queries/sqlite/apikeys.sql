-- name: CreateAPIKey :exec
INSERT INTO api_keys (
    id, name, start, prefix, key, key_prefix, user_id,
    rate_limit_enabled, rate_limit_time_window, rate_limit_max, request_count,
    remaining, refill_interval, refill_amount, last_refill_at,
    enabled, last_request, expires_at, permissions, metadata,
    created_at, updated_at
) VALUES (
    ?, ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?,
    ?, ?, ?, ?,
    ?, ?, ?, ?, ?,
    ?, ?
);

-- name: GetAPIKeyByKeyPrefix :many
SELECT * FROM api_keys WHERE key_prefix = ? AND enabled = 1;

-- name: GetAPIKeyByID :one
SELECT * FROM api_keys WHERE id = ?;

-- name: ListAPIKeysByUserID :many
SELECT * FROM api_keys WHERE user_id = ? ORDER BY created_at DESC;

-- name: UpdateAPIKey :exec
UPDATE api_keys
SET name = ?, rate_limit_enabled = ?, rate_limit_time_window = ?, rate_limit_max = ?,
    remaining = ?, refill_interval = ?, refill_amount = ?, enabled = ?,
    expires_at = ?, permissions = ?, metadata = ?, updated_at = ?
WHERE id = ?;

-- name: UpdateAPIKeyUsage :exec
UPDATE api_keys
SET request_count = ?, remaining = ?, last_request = ?, last_refill_at = ?, updated_at = ?
WHERE id = ?;

-- name: DeleteAPIKey :exec
DELETE FROM api_keys WHERE id = ?;

-- name: DeleteAPIKeysByUserID :exec
DELETE FROM api_keys WHERE user_id = ?;

-- name: DeleteExpiredAPIKeys :execrows
DELETE FROM api_keys WHERE expires_at IS NOT NULL AND expires_at < ?;
