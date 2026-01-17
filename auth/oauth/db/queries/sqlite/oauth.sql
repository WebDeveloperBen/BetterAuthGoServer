-- OAuth States
-- name: CreateOAuthState :exec
INSERT INTO
  oauth_states (
    state,
    provider,
    verifier,
    redirect_to,
    created_at,
    expires_at
  )
VALUES
  (?, ?, ?, ?, ?, ?);

-- name: GetOAuthState :one
SELECT
  *
FROM
  oauth_states
WHERE
  state = ?;

-- name: DeleteOAuthState :exec
DELETE FROM oauth_states
WHERE
  state = ?;

-- name: DeleteExpiredOAuthStates :exec
DELETE FROM oauth_states
WHERE
  expires_at < ?;

-- OAuth Accounts
-- name: CreateOAuthAccount :exec
INSERT INTO
  oauth_accounts (
    id,
    user_id,
    provider,
    provider_account_id,
    access_token,
    refresh_token,
    access_token_expires_at,
    created_at,
    updated_at
  )
VALUES
  (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetOAuthAccountByProvider :one
SELECT
  *
FROM
  oauth_accounts
WHERE
  provider = ?
  AND provider_account_id = ?;

-- name: GetOAuthAccountsByUserID :many
SELECT
  *
FROM
  oauth_accounts
WHERE
  user_id = ?;

-- name: UpdateOAuthAccount :exec
UPDATE oauth_accounts
SET
  access_token = ?,
  refresh_token = ?,
  access_token_expires_at = ?,
  updated_at = ?
WHERE
  id = ?;

-- name: DeleteOAuthAccount :exec
DELETE FROM oauth_accounts
WHERE
  id = ?;
