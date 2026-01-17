-- name: CreateAPIKey :exec
INSERT INTO api_keys (
    id, name, start, prefix, key, key_prefix, user_id,
    rate_limit_enabled, rate_limit_time_window, rate_limit_max, request_count,
    remaining, refill_interval, refill_amount, last_refill_at,
    enabled, last_request, expires_at, permissions, metadata,
    created_at, updated_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7,
    $8, $9, $10, $11,
    $12, $13, $14, $15,
    $16, $17, $18, $19, $20,
    $21, $22
);

-- name: GetAPIKeyByKeyPrefix :many
SELECT * FROM api_keys WHERE key_prefix = $1 AND enabled = true;

-- name: GetAPIKeyByID :one
SELECT * FROM api_keys WHERE id = $1;

-- name: ListAPIKeysByUserID :many
SELECT * FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC;

-- name: UpdateAPIKey :exec
UPDATE api_keys
SET name = $2, rate_limit_enabled = $3, rate_limit_time_window = $4, rate_limit_max = $5,
    remaining = $6, refill_interval = $7, refill_amount = $8, enabled = $9,
    expires_at = $10, permissions = $11, metadata = $12, updated_at = $13
WHERE id = $1;

-- name: UpdateAPIKeyUsage :exec
UPDATE api_keys
SET request_count = $2, remaining = $3, last_request = $4, last_refill_at = $5, updated_at = $6
WHERE id = $1;

-- name: DeleteAPIKey :exec
DELETE FROM api_keys WHERE id = $1;

-- name: DeleteAPIKeysByUserID :exec
DELETE FROM api_keys WHERE user_id = $1;

-- name: DeleteExpiredAPIKeys :execrows
DELETE FROM api_keys WHERE expires_at IS NOT NULL AND expires_at < $1;
