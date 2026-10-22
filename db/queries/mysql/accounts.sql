-- name: CreateAccount :exec
INSERT INTO accounts (id, user_id, provider, provider_account_id, password_hash, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetAccountByID :one
SELECT * FROM accounts WHERE id = ?;

-- name: GetAccountByUserIDAndProvider :one
SELECT * FROM accounts WHERE user_id = ? AND provider = ?;

-- name: GetAccountByProvider :one
SELECT * FROM accounts WHERE provider = ? AND provider_account_id = ?;

-- name: ListAccountsByUserID :many
SELECT * FROM accounts WHERE user_id = ?;
-- name: ListAccountsByUserIDs :many
SELECT * FROM accounts WHERE user_id IN (sqlc.slice('user_ids'));

-- name: UpdateAccount :exec
UPDATE accounts
SET provider = ?, provider_account_id = ?, password_hash = ?, updated_at = ?
WHERE id = ?;

-- name: DeleteAccount :exec
DELETE FROM accounts WHERE id = ?;

-- name: DeleteAccountsByUserID :exec
DELETE FROM accounts WHERE user_id = ?;