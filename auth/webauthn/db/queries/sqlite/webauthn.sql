-- WebAuthn Credentials

-- name: CreateWebAuthnCredential :exec
INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, sign_count, transports, created_at, last_used_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetWebAuthnCredentialByID :one
SELECT * FROM webauthn_credentials WHERE credential_id = ?;

-- name: ListWebAuthnCredentialsByUserID :many
SELECT * FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at ASC;

-- name: UpdateWebAuthnCredentialSignCount :exec
UPDATE webauthn_credentials SET sign_count = ?, last_used_at = ? WHERE id = ?;

-- name: DeleteWebAuthnCredential :exec
DELETE FROM webauthn_credentials WHERE id = ?;

-- WebAuthn Sessions

-- name: CreateWebAuthnSession :exec
INSERT INTO webauthn_sessions (id, user_id, type, data, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetWebAuthnSession :one
SELECT * FROM webauthn_sessions WHERE id = ?;

-- name: DeleteWebAuthnSession :exec
DELETE FROM webauthn_sessions WHERE id = ?;

-- name: DeleteExpiredWebAuthnSessions :exec
DELETE FROM webauthn_sessions WHERE expires_at < ?;
