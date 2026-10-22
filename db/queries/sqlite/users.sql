-- name: CreateUser :exec
INSERT INTO users (id, email, email_verified, name, image, banned, banned_at, ban_reason, role, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetUserByID :one
SELECT * FROM users WHERE id = ?;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = ?;

-- name: UpdateUser :exec
UPDATE users
SET email = ?, email_verified = ?, name = ?, image = ?, banned = ?, banned_at = ?, ban_reason = ?, role = ?, updated_at = ?
WHERE id = ?;

-- name: SetEmailVerified :exec
UPDATE users SET email_verified = ?, updated_at = ? WHERE id = ?;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = ?;

-- Admin operations

-- name: ListUsersWithQuery :many
SELECT * FROM users
WHERE (name LIKE '%' || ? || '%' OR email LIKE '%' || ? || '%')
ORDER BY created_at DESC
LIMIT ? OFFSET ?;

-- name: ListUsersWithQueryAndRole :many
SELECT * FROM users
WHERE (name LIKE '%' || ? || '%' OR email LIKE '%' || ? || '%')
AND role = ?
ORDER BY created_at DESC
LIMIT ? OFFSET ?;

-- name: ListUsersWithRole :many
SELECT * FROM users
WHERE role = ?
ORDER BY created_at DESC
LIMIT ? OFFSET ?;

-- name: ListAllUsers :many
SELECT * FROM users
ORDER BY created_at DESC
LIMIT ? OFFSET ?;

-- name: CountUsersWithQuery :one
SELECT COUNT(*) FROM users
WHERE (name LIKE '%' || ? || '%' OR email LIKE '%' || ? || '%');

-- name: CountUsersWithQueryAndRole :one
SELECT COUNT(*) FROM users
WHERE (name LIKE '%' || ? || '%' OR email LIKE '%' || ? || '%')
AND role = ?;

-- name: CountUsersWithRole :one
SELECT COUNT(*) FROM users WHERE role = ?;

-- name: CountAllUsers :one
SELECT COUNT(*) FROM users;

-- name: BanUser :exec
UPDATE users SET banned = 1, ban_reason = ?, updated_at = ? WHERE id = ?;

-- name: UnbanUser :exec
UPDATE users SET banned = 0, ban_reason = NULL, updated_at = ? WHERE id = ?;

-- name: SetUserRole :exec
UPDATE users SET role = ?, updated_at = ? WHERE id = ?;

-- Anonymous operations

-- name: SetAnonymousFlag :exec
UPDATE users SET is_anonymous = ?, updated_at = ? WHERE id = ?;

-- name: DeleteStaleAnonymousUsers :execrows
DELETE FROM users WHERE is_anonymous = 1 AND created_at < ?;

-- name: GetUserWithAnonymousStatus :one
SELECT id, email, email_verified, name, image, role, banned, ban_reason, is_anonymous, created_at, updated_at
FROM users WHERE id = ?;

-- LockUser takes SQLite's database write lock for the rest of the transaction
-- (SQLite has no row locks or FOR UPDATE; a no-op write serialises writers).
-- name: LockUser :execrows
UPDATE users SET updated_at = updated_at WHERE id = ?;
