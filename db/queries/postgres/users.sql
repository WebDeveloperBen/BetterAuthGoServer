-- name: CreateUser :exec
INSERT INTO users (id, email, email_verified, name, image, banned, banned_at, ban_reason, role, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: UpdateUser :exec
UPDATE users
SET email = $2, email_verified = $3, name = $4, image = $5, banned = $6, banned_at = $7, ban_reason = $8, role = $9, updated_at = $10
WHERE id = $1;

-- name: SetEmailVerified :exec
UPDATE users SET email_verified = $2, updated_at = $3 WHERE id = $1;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = $1;

-- Admin operations

-- name: ListUsersWithQuery :many
SELECT * FROM users
WHERE (name ILIKE '%' || $1 || '%' OR email ILIKE '%' || $1 || '%')
ORDER BY created_at DESC
OFFSET $2 LIMIT $3;

-- name: ListUsersWithQueryAndRole :many
SELECT * FROM users
WHERE (name ILIKE '%' || $1 || '%' OR email ILIKE '%' || $1 || '%')
AND role = $2
ORDER BY created_at DESC
OFFSET $3 LIMIT $4;

-- name: ListUsersWithRole :many
SELECT * FROM users
WHERE role = $1
ORDER BY created_at DESC
OFFSET $2 LIMIT $3;

-- name: ListAllUsers :many
SELECT * FROM users
ORDER BY created_at DESC
OFFSET $1 LIMIT $2;

-- name: CountUsersWithQuery :one
SELECT COUNT(*) FROM users
WHERE (name ILIKE '%' || $1 || '%' OR email ILIKE '%' || $1 || '%');

-- name: CountUsersWithQueryAndRole :one
SELECT COUNT(*) FROM users
WHERE (name ILIKE '%' || $1 || '%' OR email ILIKE '%' || $1 || '%')
AND role = $2;

-- name: CountUsersWithRole :one
SELECT COUNT(*) FROM users WHERE role = $1;

-- name: CountAllUsers :one
SELECT COUNT(*) FROM users;

-- name: BanUser :exec
UPDATE users SET banned = true, ban_reason = $2, updated_at = $3 WHERE id = $1;

-- name: UnbanUser :exec
UPDATE users SET banned = false, ban_reason = NULL, updated_at = $2 WHERE id = $1;

-- name: SetUserRole :exec
UPDATE users SET role = $2, updated_at = $3 WHERE id = $1;

-- Anonymous operations

-- name: SetAnonymousFlag :exec
UPDATE users SET is_anonymous = $2, updated_at = $3 WHERE id = $1;

-- name: DeleteStaleAnonymousUsers :execrows
DELETE FROM users WHERE is_anonymous = true AND created_at < $1;

-- name: GetUserWithAnonymousStatus :one
SELECT id, email, email_verified, name, image, role, banned, ban_reason, is_anonymous, created_at, updated_at
FROM users WHERE id = $1;

-- LockUser takes a row lock on the user for the rest of the transaction.
-- name: LockUser :one
SELECT id FROM users WHERE id = $1 FOR UPDATE;
