-- name: CreateOTPToken :exec
INSERT INTO otp_tokens (id, user_id, token_hash, type, identifier, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetOTPTokenByTokenHash :one
SELECT * FROM otp_tokens WHERE token_hash = ?;

-- name: DeleteOTPToken :exec
DELETE FROM otp_tokens WHERE id = ?;

-- name: DeleteOTPTokensByUserAndType :exec
DELETE FROM otp_tokens WHERE user_id = ? AND type = ?;

-- name: DeleteExpiredOTPTokens :exec
DELETE FROM otp_tokens WHERE expires_at < ?;