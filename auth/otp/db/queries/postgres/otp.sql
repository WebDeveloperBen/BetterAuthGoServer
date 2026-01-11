-- name: CreateOTPToken :exec
INSERT INTO otp_tokens (id, user_id, token_hash, type, identifier, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: GetOTPTokenByTokenHash :one
SELECT * FROM otp_tokens WHERE token_hash = $1;

-- name: DeleteOTPToken :exec
DELETE FROM otp_tokens WHERE id = $1;

-- name: DeleteOTPTokensByUserAndType :exec
DELETE FROM otp_tokens WHERE user_id = $1 AND type = $2;

-- name: DeleteExpiredOTPTokens :exec
DELETE FROM otp_tokens WHERE expires_at < $1;
