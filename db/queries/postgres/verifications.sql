-- name: CreateVerification :exec
INSERT INTO verifications (id, user_id, token_hash, type, identifier, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: GetVerificationByTokenHash :one
SELECT * FROM verifications WHERE token_hash = $1;

-- name: DeleteVerification :exec
DELETE FROM verifications WHERE id = $1;

-- name: DeleteVerificationsByUserIDAndType :exec
DELETE FROM verifications WHERE user_id = $1 AND type = $2;

-- name: DeleteExpiredVerifications :exec
DELETE FROM verifications WHERE expires_at < $1;
