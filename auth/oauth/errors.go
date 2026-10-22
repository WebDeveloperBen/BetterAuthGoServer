// Package oauth provides OAuth 2.0 authentication integration for the auth server.
// It handles OAuth provider configuration, user account linking, and authentication flows.
package oauth

import (
	"errors"
	"net/http"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
)

// OAuth plugin errors
var (
	ErrProviderNotFound   = errors.New("oauth: provider not found")
	ErrStateMismatch      = errors.New("oauth: state mismatch")
	ErrStateExpired       = errors.New("oauth: state expired")
	ErrStateNotFound      = errors.New("oauth: state not found")
	ErrMissingCode        = errors.New("oauth: missing code or state parameter")
	ErrNoUserInfo         = errors.New("oauth: no user info in result")
	ErrStoreRequired      = errors.New("oauth: plugin store is required")
	ErrRedirectNotAllowed = errors.New("oauth: redirect not allowed")
	ErrEmailNotVerified   = errors.New("oauth: email not verified")
	ErrNoProviders        = errors.New("oauth: at least one provider is required")

	// ErrProviderAccessDenied is returned when the provider redirects back to the callback
	// with error=access_denied: the user cancelled or denied the authorization request.
	ErrProviderAccessDenied = errors.New("oauth: access denied at the provider")

	// ErrProviderError is returned when the provider redirects back to the callback with
	// another error, or when the token exchange or the user info request fails.
	// The provider's own description is never included in responses.
	ErrProviderError = errors.New("oauth: the provider could not complete the sign-in")

	// ErrInvalidCallbackErrorRedirect is returned by Init when the target configured with
	// WithCallbackErrorRedirect is neither an absolute http(s) URL nor a path starting with
	// a single "/".
	ErrInvalidCallbackErrorRedirect = errors.New(
		"oauth: callback error redirect must be an absolute http(s) URL or a path starting with /")

	// ErrAccountExistsLinkRequired is returned when a sign-in through a provider account
	// that is not linked yet reports an email that already belongs to a user. The user
	// must sign in with an existing method and link the provider explicitly.
	ErrAccountExistsLinkRequired = errors.New("oauth: an account with this email already exists; sign in and link this provider")

	// ErrAccountAlreadyLinked is returned when a link flow targets a provider account
	// that is already linked to a different user.
	ErrAccountAlreadyLinked = errors.New("oauth: this provider account is already linked to another user")

	// ErrLinkRequiresSession is returned when a link flow is started or completed
	// without the signed-in session it is bound to.
	ErrLinkRequiresSession = errors.New("oauth: linking requires the session that started the link")

	// ErrLinkNotAllowed is returned when linking is attempted from an impersonation session.
	ErrLinkNotAllowed = errors.New("oauth: linking is not allowed from an impersonation session")
)

// Stable error codes returned in the "code" field of OAuth error responses and in the
// "error" query parameter of callback error redirects (see WithCallbackErrorRedirect).
const (
	// CodeAccessDenied: the provider redirected back with error=access_denied.
	CodeAccessDenied = "access_denied"
	// CodeProviderError: the provider redirected back with another error, or the token
	// exchange or user info request failed or returned no user.
	CodeProviderError = "provider_error"
	// CodeInvalidState: the state is unknown, expired or belongs to another provider.
	CodeInvalidState = "invalid_state"
	// CodeInvalidCallback: the callback carries no code or state and no provider error.
	CodeInvalidCallback = "invalid_callback"
	// CodeProviderNotFound: the provider is not configured.
	CodeProviderNotFound = "provider_not_found"
	// CodeInvalidRedirect: the redirect_to target is not allowed.
	CodeInvalidRedirect = "invalid_redirect"
	// CodeEmailNotVerified: the provider did not report a verified email.
	CodeEmailNotVerified = "email_not_verified"
	// CodeAccountExistsLinkRequired: the email already belongs to a user; sign in and link.
	CodeAccountExistsLinkRequired = "account_exists_link_required"
	// CodeAccountAlreadyLinked: the provider account is linked to another user.
	CodeAccountAlreadyLinked = "account_already_linked"
	// CodeLinkSessionMismatch: the link was completed without the session that started it,
	// or from an impersonation session.
	CodeLinkSessionMismatch = "link_session_mismatch"
	// CodeUserBanned: the user is banned.
	CodeUserBanned = "user_banned"
	// CodeServerError: any other failure. Internal details are never exposed.
	CodeServerError = "server_error"
)

// flowError classifies a client-facing OAuth error.
type flowError struct {
	err    error
	code   string
	status int
}

// flowErrors maps every client-facing OAuth error to its stable code and default status.
// Errors not listed here are internal: 500 with code server_error.
var flowErrors = []flowError{
	{ErrProviderAccessDenied, CodeAccessDenied, http.StatusBadRequest},
	{ErrProviderError, CodeProviderError, http.StatusBadRequest},
	{ErrNoUserInfo, CodeProviderError, http.StatusBadRequest},
	{ErrStateNotFound, CodeInvalidState, http.StatusBadRequest},
	{ErrStateExpired, CodeInvalidState, http.StatusBadRequest},
	{ErrStateMismatch, CodeInvalidState, http.StatusBadRequest},
	{ErrMissingCode, CodeInvalidCallback, http.StatusBadRequest},
	{ErrProviderNotFound, CodeProviderNotFound, http.StatusBadRequest},
	{ErrRedirectNotAllowed, CodeInvalidRedirect, http.StatusBadRequest},
	{ErrEmailNotVerified, CodeEmailNotVerified, http.StatusForbidden},
	{ErrAccountExistsLinkRequired, CodeAccountExistsLinkRequired, http.StatusConflict},
	{ErrAccountAlreadyLinked, CodeAccountAlreadyLinked, http.StatusConflict},
	{ErrLinkRequiresSession, CodeLinkSessionMismatch, http.StatusForbidden},
	{ErrLinkNotAllowed, CodeLinkSessionMismatch, http.StatusForbidden},
	{models.ErrUserBanned, CodeUserBanned, http.StatusForbidden},
}

// classifyError returns the classification of err, or nil when err is internal.
func classifyError(err error) *flowError {
	for i := range flowErrors {
		if errors.Is(err, flowErrors[i].err) {
			return &flowErrors[i]
		}
	}
	return nil
}

// errorCode returns the stable client-facing code for err; internal errors are server_error.
func errorCode(err error) string {
	if fe := classifyError(err); fe != nil {
		return fe.code
	}
	return CodeServerError
}

// statusForError maps OAuth flow errors to HTTP status codes; internal errors are 500.
func statusForError(err error) int {
	if fe := classifyError(err); fe != nil {
		return fe.status
	}
	return http.StatusInternalServerError
}
