// Package oauth provides OAuth 2.0 authentication integration for the auth server.
// It handles OAuth provider configuration, user account linking, and authentication flows.
package oauth

import "errors"

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

// Stable error codes returned in the "code" field of OAuth error responses.
const (
	CodeEmailNotVerified          = "email_not_verified"
	CodeAccountExistsLinkRequired = "account_exists_link_required"
	CodeAccountAlreadyLinked      = "account_already_linked"
	CodeLinkSessionMismatch       = "link_session_mismatch"
)

// errorCode returns the stable client-facing code for err, or "" when it has none.
func errorCode(err error) string {
	switch {
	case errors.Is(err, ErrEmailNotVerified):
		return CodeEmailNotVerified
	case errors.Is(err, ErrAccountExistsLinkRequired):
		return CodeAccountExistsLinkRequired
	case errors.Is(err, ErrAccountAlreadyLinked):
		return CodeAccountAlreadyLinked
	case errors.Is(err, ErrLinkRequiresSession):
		return CodeLinkSessionMismatch
	default:
		return ""
	}
}
