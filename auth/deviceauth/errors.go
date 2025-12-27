// Package deviceauth provides OAuth 2.0 Device Authorization Grant (RFC 8628)
// for devices with limited input capabilities.
package deviceauth

import "errors"

// Package-level errors for device authorization.
var (
	// ErrInvalidDeviceCode indicates the device code is invalid or not found.
	ErrInvalidDeviceCode = errors.New("deviceauth: invalid device code")

	// ErrExpiredDeviceCode indicates the device code has expired.
	ErrExpiredDeviceCode = errors.New("deviceauth: device code expired")

	// ErrInvalidUserCode indicates the user code is invalid or not found.
	ErrInvalidUserCode = errors.New("deviceauth: invalid user code")

	// ErrExpiredUserCode indicates the user code has expired.
	ErrExpiredUserCode = errors.New("deviceauth: user code expired")

	// ErrAuthorizationPending indicates the user has not yet approved/denied the request.
	ErrAuthorizationPending = errors.New("deviceauth: authorization pending")

	// ErrAccessDenied indicates the user denied the authorization request.
	ErrAccessDenied = errors.New("deviceauth: access denied")

	// ErrSlowDown indicates the client is polling too frequently.
	ErrSlowDown = errors.New("deviceauth: polling too frequently")

	// ErrAlreadyProcessed indicates the device code was already approved or denied.
	ErrAlreadyProcessed = errors.New("deviceauth: device code already processed")

	// ErrInvalidClient indicates the client_id is invalid.
	ErrInvalidClient = errors.New("deviceauth: invalid client")

	// ErrAuthenticationRequired indicates the user must be authenticated.
	ErrAuthenticationRequired = errors.New("deviceauth: authentication required")

	// ErrInvalidGrant indicates the grant_type is invalid.
	ErrInvalidGrant = errors.New("deviceauth: invalid grant type")

	// ErrFailedToCreateSession indicates session creation failed.
	ErrFailedToCreateSession = errors.New("deviceauth: failed to create session")
)

// OAuth 2.0 error codes as defined in RFC 8628.
const (
	// OAuth2ErrorAuthorizationPending - the authorization request is pending.
	OAuth2ErrorAuthorizationPending = "authorization_pending"

	// OAuth2ErrorSlowDown - the client should slow down polling.
	OAuth2ErrorSlowDown = "slow_down"

	// OAuth2ErrorAccessDenied - the user denied the request.
	OAuth2ErrorAccessDenied = "access_denied"

	// OAuth2ErrorExpiredToken - the device code has expired.
	OAuth2ErrorExpiredToken = "expired_token"

	// OAuth2ErrorInvalidGrant - the grant is invalid.
	OAuth2ErrorInvalidGrant = "invalid_grant"

	// OAuth2ErrorInvalidClient - the client is invalid.
	OAuth2ErrorInvalidClient = "invalid_client"

	// OAuth2ErrorInvalidRequest - the request is malformed.
	OAuth2ErrorInvalidRequest = "invalid_request"
)

// DeviceCodeGrantType is the OAuth 2.0 grant type for device authorization.
const DeviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"
