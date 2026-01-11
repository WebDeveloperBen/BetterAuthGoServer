-- name: CreateSession :exec
INSERT INTO sessions (id, user_id, token_hash, ip_address, user_agent, created_at, expires_at, last_used, impersonated_by)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetSessionByID :one
SELECT * FROM sessions WHERE id = ?;

-- name: GetSessionByTokenHash :one
SELECT * FROM sessions WHERE token_hash = ?;

-- name: ListSessionsByUserID :many
SELECT * FROM sessions WHERE user_id = ? ORDER BY created_at DESC;

-- name: UpdateSessionLastUsed :exec
UPDATE sessions SET last_used = ? WHERE id = ?;

-- name: DeleteSession :exec
DELETE FROM sessions WHERE id = ?;

-- name: DeleteSessionsByUserID :exec
DELETE FROM sessions WHERE user_id = ?;

-- name: DeleteExpiredSessions :exec
DELETE FROM sessions WHERE expires_at < ?;