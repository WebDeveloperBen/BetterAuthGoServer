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
  ($1, $2, $3, $4, $5, $6);

-- name: GetOAuthState :one
SELECT
  *
FROM
  oauth_states
WHERE
  state = $1;

-- name: DeleteOAuthState :exec
DELETE FROM oauth_states
WHERE
  state = $1;

-- name: DeleteExpiredOAuthStates :exec
DELETE FROM oauth_states
WHERE
  expires_at < $1;

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
  ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: GetOAuthAccountByProvider :one
SELECT
  *
FROM
  oauth_accounts
WHERE
  provider = $1
  AND provider_account_id = $2;

-- name: GetOAuthAccountsByUserID :many
SELECT
  *
FROM
  oauth_accounts
WHERE
  user_id = $1;

-- name: UpdateOAuthAccount :exec
UPDATE oauth_accounts
SET
  access_token = $2,
  refresh_token = $3,
  access_token_expires_at = $4,
  updated_at = $5
WHERE
  id = $1;

-- name: DeleteOAuthAccount :exec
DELETE FROM oauth_accounts
WHERE
  id = $1;
