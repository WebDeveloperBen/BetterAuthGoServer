-- WebAuthn Credentials

-- name: CreateWebAuthnCredential :exec
INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, sign_count, transports, created_at, last_used_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: GetWebAuthnCredentialByID :one
SELECT * FROM webauthn_credentials WHERE credential_id = $1;

-- name: ListWebAuthnCredentialsByUserID :many
SELECT * FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at ASC;

-- name: UpdateWebAuthnCredentialSignCount :exec
UPDATE webauthn_credentials SET sign_count = $2, last_used_at = $3 WHERE id = $1;

-- name: DeleteWebAuthnCredential :exec
DELETE FROM webauthn_credentials WHERE id = $1;

-- WebAuthn Sessions

-- name: CreateWebAuthnSession :exec
INSERT INTO webauthn_sessions (id, user_id, type, data, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetWebAuthnSession :one
SELECT * FROM webauthn_sessions WHERE id = $1;

-- name: DeleteWebAuthnSession :exec
DELETE FROM webauthn_sessions WHERE id = $1;

-- name: DeleteExpiredWebAuthnSessions :exec
DELETE FROM webauthn_sessions WHERE expires_at < $1;
