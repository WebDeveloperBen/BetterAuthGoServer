// Package oauth provides OAuth 2.0 authentication integration for the auth server.
// It handles OAuth provider configuration, user account linking, and authentication flows.
package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	oauthdb "github.com/webdeveloperben/BetterAuthGoServer/auth/oauth/db"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
	"github.com/webdeveloperben/BetterAuthGoServer/db"
	"golang.org/x/oauth2"
)

// Response types

type oauthProvidersResponse struct {
	Providers []string `json:"providers"`
}

// ListOAuthProvidersHandler returns a handler for GET /oauth/providers
func (p *Plugin) ListOAuthProvidersHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		providers := p.ConfiguredProviders()
		_ = writeJSON(w, http.StatusOK, oauthProvidersResponse{
			Providers: providers,
		})
	}
}

// OAuthBeginHandler returns a handler for GET /oauth/:provider
func (p *Plugin) OAuthBeginHandler() func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, r *http.Request, provider string) {
		redirectTo := r.URL.Query().Get("redirect_to")
		if redirectTo != "" && !p.isRedirectAllowed(redirectTo) {
			p.failFlow(w, r, provider, false, ErrRedirectNotAllowed)
			return
		}

		result, err := p.service.Begin(r.Context(), provider, redirectTo)
		if err != nil {
			p.failFlow(w, r, provider, false, err)
			return
		}

		http.Redirect(w, r, result.URL, http.StatusFound)
	}
}

// OAuthLinkBeginHandler returns a handler for POST /oauth/{provider}/link.
// The route requires an authenticated session. It starts an OAuth flow whose state is
// bound to the current user and session and responds with {"url": "<provider authorize URL>"};
// the client navigates the browser to that URL.
func (p *Plugin) OAuthLinkBeginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := p.ctx.Sessions.GetFromRequest(r)
		if session == nil {
			writeError(w, http.StatusUnauthorized, ErrLinkRequiresSession)
			return
		}
		if session.IsImpersonation() {
			writeError(w, http.StatusForbidden, ErrLinkNotAllowed)
			return
		}

		redirectTo := r.URL.Query().Get("redirect_to")
		if redirectTo != "" && !p.isRedirectAllowed(redirectTo) {
			writeError(w, http.StatusBadRequest, ErrRedirectNotAllowed)
			return
		}

		result, err := p.service.BeginLink(r.Context(), r.PathValue("provider"), redirectTo, session.UserID, session.ID)
		if err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, ErrProviderNotFound) {
				status = http.StatusBadRequest
			}
			writeError(w, status, err)
			return
		}

		_ = writeJSON(w, http.StatusOK, map[string]string{"url": result.URL})
	}
}

// OAuthCallbackHandler returns a handler for GET /oauth/:provider/callback.
// Sign-in states run the sign-in rules; link states run the explicit-link rules.
func (p *Plugin) OAuthCallbackHandler() func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, r *http.Request, provider string) {
		query := r.URL.Query()
		code := query.Get("code")
		state := query.Get("state")

		// OAuth 2.0 error response (RFC 6749 section 4.1.2.1). error_description is never echoed.
		if providerError := query.Get("error"); providerError != "" {
			p.failProviderError(w, r, provider, providerError, state)
			return
		}

		if code == "" || state == "" {
			p.failFlow(w, r, provider, false, ErrMissingCode)
			return
		}

		// Complete OAuth flow
		oauthResult, oauthState, err := p.service.Complete(r.Context(), provider, code, state)
		if err != nil {
			p.failFlow(w, r, provider, oauthState != nil && oauthState.IsLink(), err)
			return
		}
		if oauthResult.UserInfo == nil || oauthResult.UserInfo.ID == "" {
			p.failFlow(w, r, provider, oauthState.IsLink(), ErrNoUserInfo)
			return
		}

		if oauthState.IsLink() {
			p.completeLink(w, r, provider, oauthResult, oauthState)
			return
		}
		p.completeSignIn(w, r, provider, oauthResult, oauthState)
	}
}

// failProviderError handles a callback on which the provider reported an error. The state
// is consumed so it cannot be completed later, and tells whether a link flow failed.
func (p *Plugin) failProviderError(w http.ResponseWriter, r *http.Request, provider, providerError, stateValue string) {
	state, err := p.service.Discard(r.Context(), provider, stateValue)
	if errors.Is(err, ErrProviderNotFound) {
		p.failFlow(w, r, provider, false, err)
		return
	}
	// Any other lookup failure only loses the flow kind: the provider's error is still
	// the outcome to report, and the unconsumed state expires on its own.
	isLink := err == nil && state != nil && state.IsLink()

	flowErr := ErrProviderError
	if providerError == "access_denied" {
		flowErr = ErrProviderAccessDenied
	}
	p.failFlow(w, r, provider, isLink, flowErr)
}

// completeSignIn resolves the user for a sign-in callback, creates a session and responds.
func (p *Plugin) completeSignIn(w http.ResponseWriter, r *http.Request, provider string, result *AuthResult, state *State) {
	user, err := p.signInUser(r.Context(), provider, result)
	if err != nil {
		p.failFlow(w, r, provider, false, err)
		return
	}

	// Create session
	session, err := p.auth.CreateSessionForUser(r.Context(), user.ID, r)
	if err != nil {
		p.failFlow(w, r, provider, false, err)
		return
	}

	// WriteAuthResponse handles both cookie and JWT modes
	if err := p.ctx.Sessions.WriteAuthResponse(r.Context(), w, session, user); err != nil {
		p.failFlow(w, r, provider, false, err)
		return
	}

	if p.redirectAfterCallback(w, r, provider, state) {
		return
	}

	_ = writeJSON(w, http.StatusOK, map[string]any{
		"user":    toUserResponse(user),
		"session": toSessionResponse(session),
	})
}

// signInUser applies the sign-in rules:
//  1. a provider account that is already linked signs in as its user (unless banned);
//  2. otherwise the provider must report a verified email;
//  3. an email that already belongs to a user is a conflict: the user must sign in and link explicitly;
//  4. otherwise a new user and provider account are created atomically.
//
// Rejections write nothing. If a concurrent sign-in through the same provider identity
// wins the race to create the user, the loser re-resolves and signs in as that user (rule 1).
func (p *Plugin) signInUser(ctx context.Context, provider string, result *AuthResult) (*plugin.User, error) {
	info := result.UserInfo

	existingAccount, err := p.accountStore.GetAccountByProvider(ctx, provider, info.ID)
	if err != nil {
		return nil, err
	}
	if existingAccount != nil {
		return p.signInLinkedAccount(ctx, existingAccount, result)
	}

	if info.Email == "" || !info.EmailVerified {
		return nil, ErrEmailNotVerified
	}

	_, err = p.auth.GetPluginUserByEmail(ctx, info.Email)
	switch {
	case err == nil:
		return nil, ErrAccountExistsLinkRequired
	case !errors.Is(err, models.ErrUserNotFound):
		return nil, err
	}

	account, err := p.newAccount("", provider, info.ID, result.OAuthToken)
	if err != nil {
		return nil, err
	}

	var image *string
	if info.Picture != "" {
		image = &info.Picture
	}

	var user *plugin.User
	err = p.retryOnDeadlock(func() error {
		var createErr error
		user, createErr = p.auth.CreatePluginUserTx(ctx, plugin.CreateUserRequest{
			Email:         info.Email,
			Name:          info.Name,
			EmailVerified: true,
			Image:         image,
		}, func(ctx context.Context, tx db.DBTX, user *plugin.User) error {
			accounts, err := p.accountStoreFor(tx)
			if err != nil {
				return err
			}
			account.UserID = user.ID
			return accounts.CreateAccount(ctx, account)
		})
		return createErr
	})
	if err != nil {
		if !errors.Is(err, models.ErrUserAlreadyExists) && !p.accountStore.IsUniqueViolation(err) {
			return nil, err
		}
		// A concurrent request created the user (email) or the provider account first.
		// The transaction rolled back, so re-resolve against what was committed.
		existingAccount, lookupErr := p.accountStore.GetAccountByProvider(ctx, provider, info.ID)
		if lookupErr != nil {
			return nil, lookupErr
		}
		if existingAccount != nil {
			return p.signInLinkedAccount(ctx, existingAccount, result)
		}
		return nil, ErrAccountExistsLinkRequired
	}

	// Fire OAuth account linked hook (ignore errors - hook is for notifications/side effects)
	_ = p.auth.FireOAuthAccountLinked(ctx, user.ID, provider, info.ID)

	return user, nil
}

// signInLinkedAccount signs in as the user an already-linked provider account belongs to.
// Banned users are refused before any session is created.
func (p *Plugin) signInLinkedAccount(ctx context.Context, account *OAuthAccount, result *AuthResult) (*plugin.User, error) {
	user, err := p.auth.GetPluginUser(ctx, account.UserID)
	if err != nil {
		return nil, err
	}
	if user.Banned {
		return nil, models.ErrUserBanned
	}
	if p.requireEmailVerification && !user.EmailVerified {
		return nil, ErrEmailNotVerified
	}
	if err := p.refreshAccountTokens(ctx, account, result.OAuthToken); err != nil {
		return nil, err
	}
	return user, nil
}

// completeLink applies the explicit-link rules to a callback whose state was started by
// POST /oauth/{provider}/link. No session is created.
func (p *Plugin) completeLink(w http.ResponseWriter, r *http.Request, provider string, result *AuthResult, state *State) {
	ctx := r.Context()

	session, err := p.auth.GetPluginSessionFromRequest(r)
	if err != nil {
		p.failFlow(w, r, provider, true, err)
		return
	}
	if session == nil || state.LinkUserID == nil || state.LinkSessionID == nil ||
		session.ID != *state.LinkSessionID || session.UserID != *state.LinkUserID {
		p.failFlow(w, r, provider, true, ErrLinkRequiresSession)
		return
	}
	if session.IsImpersonation() {
		p.failFlow(w, r, provider, true, ErrLinkNotAllowed)
		return
	}

	user, err := p.auth.GetPluginUser(ctx, session.UserID)
	if err != nil {
		p.failFlow(w, r, provider, true, err)
		return
	}
	if user.Banned {
		p.failFlow(w, r, provider, true, models.ErrUserBanned)
		return
	}

	if err := p.linkAccount(ctx, user.ID, provider, result); err != nil {
		p.failFlow(w, r, provider, true, err)
		return
	}

	if p.redirectAfterCallback(w, r, provider, state) {
		return
	}

	_ = writeJSON(w, http.StatusOK, map[string]any{
		"linked":   true,
		"provider": provider,
		"user":     toUserResponse(user),
	})
}

// linkAccount links the provider account to userID. Linking an account the user already
// owns is idempotent; linking an account owned by another user is a conflict.
// Email verification is not required: the user proved control of both identities.
func (p *Plugin) linkAccount(ctx context.Context, userID, provider string, result *AuthResult) error {
	info := result.UserInfo

	existing, err := p.accountStore.GetAccountByProvider(ctx, provider, info.ID)
	if err != nil {
		return err
	}
	if existing != nil {
		if existing.UserID != userID {
			return ErrAccountAlreadyLinked
		}
		return p.refreshAccountTokens(ctx, existing, result.OAuthToken)
	}

	account, err := p.newAccount(userID, provider, info.ID, result.OAuthToken)
	if err != nil {
		return err
	}
	if err := p.retryOnDeadlock(func() error { return p.accountStore.CreateAccount(ctx, account) }); err != nil {
		if !p.accountStore.IsUniqueViolation(err) {
			return err
		}
		// A concurrent link or sign-in created this provider account first.
		winner, lookupErr := p.accountStore.GetAccountByProvider(ctx, provider, info.ID)
		if lookupErr != nil {
			return lookupErr
		}
		if winner != nil && winner.UserID == userID {
			return nil
		}
		return ErrAccountAlreadyLinked
	}

	// Fire OAuth account linked hook (ignore errors - hook is for notifications/side effects)
	_ = p.auth.FireOAuthAccountLinked(ctx, userID, provider, info.ID)
	return nil
}

// retryOnDeadlock runs fn again, up to three attempts in total, while the database aborts
// it as a deadlock or serialization victim. Concurrent inserts of the same unique key can
// deadlock on MySQL; retrying turns that into the ordinary unique-violation outcome.
func (p *Plugin) retryOnDeadlock(fn func() error) error {
	var err error
	for range 3 {
		if err = fn(); err == nil || !p.accountStore.IsDeadlock(err) {
			return err
		}
	}
	return err
}

// redirectAfterCallback redirects to the state's redirect target when one was requested.
// It reports whether a response was written.
func (p *Plugin) redirectAfterCallback(w http.ResponseWriter, r *http.Request, provider string, state *State) bool {
	if state == nil || state.RedirectTo == nil || *state.RedirectTo == "" {
		return false
	}
	redirectTo := *state.RedirectTo
	if !p.isRedirectAllowed(redirectTo) {
		p.failFlow(w, r, provider, state.IsLink(), ErrRedirectNotAllowed)
		return true
	}
	http.Redirect(w, r, redirectTo, http.StatusFound)
	return true
}

// failFlow responds to a failed sign-in begin or callback. With WithCallbackErrorRedirect
// it redirects the browser to the configured target with the stable error code, the
// provider and flow=link for link flows; otherwise it writes the JSON error.
func (p *Plugin) failFlow(w http.ResponseWriter, r *http.Request, provider string, isLink bool, err error) {
	status := statusForError(err)
	if p.callbackErrorRedirect == nil {
		writeError(w, status, err)
		return
	}

	_, code := publicError(status, err)
	target := *p.callbackErrorRedirect
	query := target.Query()
	query.Set("error", code)
	if provider != "" {
		query.Set("provider", provider)
	}
	if isLink {
		query.Set("flow", "link")
	}
	target.RawQuery = query.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

// newAccount builds a provider account with encrypted tokens.
func (p *Plugin) newAccount(userID, provider, providerAccountID string, token *oauth2.Token) (*OAuthAccount, error) {
	now := time.Now()
	account := &OAuthAccount{
		ID:                generateID(),
		UserID:            userID,
		Provider:          provider,
		ProviderAccountID: providerAccountID,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err := p.applyTokens(account, token); err != nil {
		return nil, err
	}
	return account, nil
}

// refreshAccountTokens stores the latest provider tokens on an existing account.
func (p *Plugin) refreshAccountTokens(ctx context.Context, account *OAuthAccount, token *oauth2.Token) error {
	if err := p.applyTokens(account, token); err != nil {
		return err
	}
	account.UpdatedAt = time.Now()
	return p.accountStore.UpdateAccount(ctx, account)
}

func (p *Plugin) applyTokens(account *OAuthAccount, token *oauth2.Token) error {
	if token == nil {
		return nil
	}
	if token.AccessToken != "" {
		encrypted, err := p.service.EncryptToken(token.AccessToken)
		if err != nil {
			return err
		}
		account.AccessToken = encrypted
	}
	if token.RefreshToken != "" {
		encrypted, err := p.service.EncryptToken(token.RefreshToken)
		if err != nil {
			return err
		}
		account.RefreshToken = encrypted
	}
	if !token.Expiry.IsZero() {
		expiry := token.Expiry
		account.AccessTokenExpiresAt = &expiry
	}
	return nil
}

// accountStoreFor returns an account store bound to tx, or the plugin's store when tx is nil.
func (p *Plugin) accountStoreFor(tx db.DBTX) (*AccountStoreAdapter, error) {
	if tx == nil {
		return p.accountStore, nil
	}
	store, err := oauthdb.New(tx, p.ctx.Dialect)
	if err != nil {
		return nil, err
	}
	return NewAccountStoreAdapter(store), nil
}

// Helper functions (adapted from handlers package)
func writeJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

// writeError writes {"error": message, "code": code}; see publicError.
func writeError(w http.ResponseWriter, status int, err error) {
	message, code := publicError(status, err)
	_ = writeJSON(w, status, map[string]string{"error": message, "code": code})
}

// publicError returns the client-facing message and stable code for err. Only the message
// of the classified sentinel is exposed, never wrapped details; 5xx responses and
// unclassified errors get the status text and code server_error.
func publicError(status int, err error) (message, code string) {
	fe := classifyError(err)
	if status >= http.StatusInternalServerError || fe == nil {
		return http.StatusText(status), CodeServerError
	}
	return fe.err.Error(), fe.code
}

// OAuthDynamicHandler handles dynamic OAuth routes (/oauth/:provider and /oauth/:provider/callback)
func (p *Plugin) OAuthDynamicHandler() http.HandlerFunc {
	oauthBegin := p.OAuthBeginHandler()
	oauthCallback := p.OAuthCallbackHandler()

	return func(w http.ResponseWriter, r *http.Request) {
		provider, isCallback := parseOAuthPath(r.URL.Path)
		if provider == "" {
			writeError(w, http.StatusNotFound, ErrProviderNotFound)
			return
		}

		if isCallback {
			oauthCallback(w, r, provider)
		} else {
			oauthBegin(w, r, provider)
		}
	}
}

// parseOAuthPath extracts provider and action from /oauth/:provider or /oauth/:provider/callback.
// Any other shape yields an empty provider.
func parseOAuthPath(path string) (provider string, isCallback bool) {
	path = strings.TrimPrefix(path, "/oauth/")
	parts := strings.Split(path, "/")

	if parts[0] == "" {
		return "", false
	}

	switch {
	case len(parts) == 1:
		return parts[0], false
	case len(parts) == 2 && parts[1] == "callback":
		return parts[0], true
	default:
		return "", false
	}
}

// Response helper functions
func toUserResponse(user *plugin.User) map[string]any {
	return map[string]any{
		"id":             user.ID,
		"email":          user.Email,
		"email_verified": user.EmailVerified,
		"name":           user.Name,
		"image":          user.Image,
		"role":           user.Role,
		"banned":         user.Banned,
		"created_at":     user.CreatedAt,
		"updated_at":     user.UpdatedAt,
	}
}

func toSessionResponse(session *plugin.Session) map[string]any {
	return map[string]any{
		"id":         session.ID,
		"user_id":    session.UserID,
		"ip_address": session.IPAddress,
		"user_agent": session.UserAgent,
		"created_at": session.CreatedAt,
		"expires_at": session.ExpiresAt,
	}
}

func generateID() string {
	return uuid.New().String()
}

func (p *Plugin) isRedirectAllowed(target string) bool {
	if p.allowRelativeRedirects && strings.HasPrefix(target, "/") && !strings.HasPrefix(target, "//") {
		return true
	}

	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}

	origin := parsed.Scheme + "://" + parsed.Host
	for _, trusted := range p.trustedRedirectOrigins {
		if origin == trusted {
			return true
		}
	}

	if p.ctx.BaseURL != "" {
		baseOrigin := originFromBaseURL(p.ctx.BaseURL)
		if baseOrigin != "" && origin == baseOrigin {
			return true
		}
	}

	return false
}

func originFromBaseURL(baseURL string) string {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

// OAuthToken represents OAuth token information
type OAuthToken struct {
	AccessToken  string
	RefreshToken string
	Expiry       time.Time
}
