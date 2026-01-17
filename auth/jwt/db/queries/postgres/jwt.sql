-- name: RevokeJWTToken :exec
INSERT INTO jwt_revoked_tokens (id, expires_at, revoked_at)
VALUES ($1, $2, $3)
ON CONFLICT (id) DO NOTHING;

-- name: IsJWTTokenRevoked :one
SELECT EXISTS(SELECT 1 FROM jwt_revoked_tokens WHERE id = $1) AS revoked;

-- name: DeleteExpiredRevokedTokens :exec
DELETE FROM jwt_revoked_tokens WHERE expires_at < $1;

-- JWT Key Management

-- name: CreateJWTKey :exec
INSERT INTO jwt_keys (id, algorithm, use, kty, status, private_key_enc, public_key_jwk, activated_at, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- name: GetJWTKeyByID :one
SELECT * FROM jwt_keys WHERE id = $1;

-- name: GetActiveJWTKey :one
SELECT * FROM jwt_keys WHERE algorithm = $1 AND status = 'active' LIMIT 1;

-- name: GetJWTKeysForVerification :many
SELECT * FROM jwt_keys
WHERE algorithm = $1
  AND status IN ('active', 'rotating')
  AND (expires_at IS NULL OR expires_at > $2)
ORDER BY activated_at DESC;

-- name: GetJWTKeyForVerification :one
SELECT * FROM jwt_keys
WHERE id = $1
  AND status IN ('active', 'rotating')
  AND (expires_at IS NULL OR expires_at > $2);

-- name: RotateActiveJWTKeys :exec
UPDATE jwt_keys
SET status = 'rotating', rotated_at = $1, expires_at = $2, updated_at = $3
WHERE algorithm = $4 AND status = 'active';

-- name: RetireExpiredJWTKeys :execrows
UPDATE jwt_keys
SET status = 'retired', updated_at = $1
WHERE status = 'rotating' AND expires_at < $2;

-- name: DeleteJWTKey :exec
DELETE FROM jwt_keys WHERE id = $1;
