-- name: CreateAccount :exec
INSERT INTO accounts (id, user_id, provider, provider_account_id, password_hash, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: GetAccountByID :one
SELECT * FROM accounts WHERE id = $1;

-- name: GetAccountByUserIDAndProvider :one
SELECT * FROM accounts WHERE user_id = $1 AND provider = $2;

-- name: GetAccountByProvider :one
SELECT * FROM accounts WHERE provider = $1 AND provider_account_id = $2;

-- name: ListAccountsByUserID :many
SELECT * FROM accounts WHERE user_id = $1;

-- name: UpdateAccount :exec
UPDATE accounts
SET provider = $2, provider_account_id = $3, password_hash = $4, updated_at = $5
WHERE id = $1;

-- name: DeleteAccount :exec
DELETE FROM accounts WHERE id = $1;

-- name: DeleteAccountsByUserID :exec
DELETE FROM accounts WHERE user_id = $1;
