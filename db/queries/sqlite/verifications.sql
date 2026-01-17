-- name: CreateVerification :exec
INSERT INTO verifications (id, user_id, token_hash, type, identifier, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetVerificationByTokenHash :one
SELECT * FROM verifications WHERE token_hash = ?;

-- name: DeleteVerification :exec
DELETE FROM verifications WHERE id = ?;

-- name: DeleteVerificationsByUserIDAndType :exec
DELETE FROM verifications WHERE user_id = ? AND type = ?;

-- name: DeleteExpiredVerifications :exec
DELETE FROM verifications WHERE expires_at < ?;
