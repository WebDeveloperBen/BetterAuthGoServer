-- name: RevokeJWTToken :exec
INSERT IGNORE INTO jwt_revoked_tokens (id, expires_at, revoked_at)
VALUES (?, ?, ?);

-- name: IsJWTTokenRevoked :one
SELECT EXISTS(SELECT 1 FROM jwt_revoked_tokens WHERE id = ?) AS revoked;

-- name: DeleteExpiredRevokedTokens :exec
DELETE FROM jwt_revoked_tokens WHERE expires_at < ?;

-- JWT Key Management

-- name: CreateJWTKey :exec
INSERT INTO jwt_keys (id, algorithm, `use`, kty, status, private_key_enc, public_key_jwk, activated_at, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetJWTKeyByID :one
SELECT * FROM jwt_keys WHERE id = ?;

-- name: GetActiveJWTKey :one
SELECT * FROM jwt_keys WHERE algorithm = ? AND status = 'active' LIMIT 1;

-- name: GetJWTKeysForVerification :many
SELECT * FROM jwt_keys
WHERE algorithm = ?
  AND status IN ('active', 'rotating')
  AND (expires_at IS NULL OR expires_at > ?)
ORDER BY activated_at DESC;

-- name: GetJWTKeyForVerification :one
SELECT * FROM jwt_keys
WHERE id = ?
  AND status IN ('active', 'rotating')
  AND (expires_at IS NULL OR expires_at > ?);

-- name: RotateActiveJWTKeys :exec
UPDATE jwt_keys
SET status = 'rotating', rotated_at = ?, expires_at = ?, updated_at = ?
WHERE algorithm = ? AND status = 'active';

-- name: RetireExpiredJWTKeys :execrows
UPDATE jwt_keys
SET status = 'retired', updated_at = ?
WHERE status = 'rotating' AND expires_at < ?;

-- name: DeleteJWTKey :exec
DELETE FROM jwt_keys WHERE id = ?;