-- name: CreateSession :exec
INSERT INTO sessions (id, user_id, token_hash, ip_address, user_agent, created_at, expires_at, last_used, impersonated_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: GetSessionByID :one
SELECT * FROM sessions WHERE id = $1;

-- name: GetSessionByTokenHash :one
SELECT * FROM sessions WHERE token_hash = $1;

-- name: ListSessionsByUserID :many
SELECT * FROM sessions WHERE user_id = $1 ORDER BY created_at DESC;

-- name: UpdateSessionLastUsed :exec
UPDATE sessions SET last_used = $2 WHERE id = $1;

-- name: DeleteSession :exec
DELETE FROM sessions WHERE id = $1;

-- name: DeleteSessionsByUserID :exec
DELETE FROM sessions WHERE user_id = $1;

-- name: DeleteExpiredSessions :exec
DELETE FROM sessions WHERE expires_at < $1;
