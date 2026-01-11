// Package oauth provides OAuth 2.0 authentication integration for the auth server.
// It handles OAuth provider configuration, user account linking, and authentication flows.
package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// Response types

type oauthProvidersResponse struct {
	Providers []string `json:"providers"`
}

// ListOAuthProvidersHandler returns a handler for GET /oauth/providers
func (p *Plugin) ListOAuthProvidersHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		providers := p.service.ListProviders()
		_ = writeJSON(w, http.StatusOK, oauthProvidersResponse{
			Providers: providers,
		})
	}
}

// OAuthBeginHandler returns a handler for GET /oauth/:provider
func (p *Plugin) OAuthBeginHandler() func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, r *http.Request, provider string) {
		redirectTo := r.URL.Query().Get("redirect_to")

		result, err := p.service.Begin(r.Context(), provider, redirectTo)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		http.Redirect(w, r, result.URL, http.StatusFound)
	}
}

// OAuthCallbackHandler returns a handler for GET /oauth/:provider/callback
func (p *Plugin) OAuthCallbackHandler() func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, r *http.Request, provider string) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		if code == "" || state == "" {
			writeError(w, http.StatusBadRequest, ErrMissingCode)
			return
		}

		// Complete OAuth flow
		oauthResult, oauthState, err := p.service.Complete(r.Context(), provider, code, state)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		// Create or update user account
		user, err := p.completeOAuthUserCreation(r.Context(), provider, oauthResult)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		// Create session
		session, err := p.auth.CreateSessionForUser(r.Context(), user.ID, r)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		// WriteAuthResponse handles both cookie and JWT modes
		if err := p.ctx.Sessions.WriteAuthResponse(r.Context(), w, session, user); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		// Redirect to the URL from state if provided, otherwise return JSON
		redirectTo := ""
		if oauthState != nil && oauthState.RedirectTo != nil {
			redirectTo = *oauthState.RedirectTo
		}

		if redirectTo != "" {
			http.Redirect(w, r, redirectTo, http.StatusFound)
			return
		}

		_ = writeJSON(w, http.StatusOK, map[string]any{
			"user":    toUserResponse(user),
			"session": toSessionResponse(session),
		})
	}
}

// completeOAuthUserCreation handles the OAuth user creation/update logic
func (p *Plugin) completeOAuthUserCreation(ctx context.Context, provider string, result *AuthResult) (*plugin.User, error) {
	userInfo := result.UserInfo
	if userInfo == nil {
		return nil, ErrNoUserInfo
	}

	// Use the account store initialized in Init
	accountStore := p.accountStore

	// Try to find existing OAuth account by provider and provider account ID
	existingAccount, err := accountStore.GetAccountByProvider(ctx, provider, userInfo.ID)
	if err != nil {
		return nil, err
	}

	if existingAccount != nil {
		// Update existing account and return user
		user, err := p.auth.GetPluginUser(ctx, existingAccount.UserID)
		if err != nil {
			return nil, err
		}

		// Update OAuth tokens
		if result.OAuthToken.AccessToken != "" {
			encrypted, err := p.service.EncryptToken(result.OAuthToken.AccessToken)
			if err != nil {
				return nil, err
			}
			existingAccount.AccessToken = encrypted
		}

		if result.OAuthToken.RefreshToken != "" {
			encrypted, err := p.service.EncryptToken(result.OAuthToken.RefreshToken)
			if err != nil {
				return nil, err
			}
			existingAccount.RefreshToken = encrypted
		}

		if !result.OAuthToken.Expiry.IsZero() {
			existingAccount.AccessTokenExpiresAt = &result.OAuthToken.Expiry
		}

		// Update account in database
		if err := accountStore.UpdateAccount(ctx, existingAccount); err != nil {
			return nil, err
		}

		return user, nil
	}

	// Check if user exists by email
	existingUser, err := p.auth.GetPluginUserByEmail(ctx, userInfo.Email)
	if err != nil {
		// ErrUserNotFound is expected if user doesn't exist
		existingUser = nil
	}

	var user *plugin.User
	if existingUser != nil {
		// Use existing user
		user = existingUser
	} else {
		// Create new user
		imagePtr := &userInfo.Picture
		user, err = p.auth.CreatePluginUser(ctx, plugin.CreateUserRequest{
			Email:         userInfo.Email,
			Name:          userInfo.Name,
			EmailVerified: userInfo.EmailVerified,
			Image:         imagePtr,
		})
		if err != nil {
			return nil, err
		}
	}

	// Create OAuth account to link the provider
	account := &OAuthAccount{
		ID:                generateID(),
		UserID:            user.ID,
		Provider:          provider,
		ProviderAccountID: userInfo.ID,
	}

	if result.OAuthToken.AccessToken != "" {
		encrypted, err := p.service.EncryptToken(result.OAuthToken.AccessToken)
		if err != nil {
			return nil, err
		}
		account.AccessToken = encrypted
	}

	if result.OAuthToken.RefreshToken != "" {
		encrypted, err := p.service.EncryptToken(result.OAuthToken.RefreshToken)
		if err != nil {
			return nil, err
		}
		account.RefreshToken = encrypted
	}

	if !result.OAuthToken.Expiry.IsZero() {
		account.AccessTokenExpiresAt = &result.OAuthToken.Expiry
	}

	// Create OAuth account in database
	if err := accountStore.CreateAccount(ctx, account); err != nil {
		return nil, err
	}

	// Fire OAuth account linked hook (ignore errors - hook is for notifications/side effects)
	_ = p.auth.FireOAuthAccountLinked(ctx, user.ID, provider, userInfo.ID)

	return user, nil
}

// Helper functions (adapted from handlers package)
func writeJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	_ = writeJSON(w, status, map[string]string{"error": err.Error()})
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

// parseOAuthPath extracts provider and action from /oauth/:provider or /oauth/:provider/callback
func parseOAuthPath(path string) (provider string, isCallback bool) {
	path = strings.TrimPrefix(path, "/oauth/")
	parts := strings.Split(path, "/")

	if len(parts) == 0 || parts[0] == "" {
		return "", false
	}

	provider = parts[0]
	isCallback = len(parts) >= 2 && parts[1] == "callback"
	return provider, isCallback
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

// OAuthToken represents OAuth token information
type OAuthToken struct {
	AccessToken  string
	RefreshToken string
	Expiry       time.Time
}
