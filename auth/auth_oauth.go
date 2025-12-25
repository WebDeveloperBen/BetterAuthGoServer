package auth

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/oauth"
)

// OAuthService manages OAuth authentication
type OAuthService struct {
	*oauth.Service
}

// RegisterOAuthProvider registers an OAuth provider with the auth system
func (a *Auth) RegisterOAuthProvider(provider oauth.Provider) {
	if a.oauth == nil {
		a.oauth = &OAuthService{
			Service: oauth.NewService(a.oauthStateStore(), a.tokenHasher, a.tokenEncryptor),
		}
	}
	a.oauth.RegisterProvider(provider)
}

// BeginOAuth starts an OAuth flow
func (a *Auth) BeginOAuth(ctx context.Context, providerName string, redirectTo string) (*oauth.AuthStart, error) {
	if a.oauth == nil {
		return nil, ErrOAuthProviderNotFound
	}

	// Validate redirect_to against TrustedOrigins if provided
	if redirectTo != "" {
		if !a.isValidRedirectURL(redirectTo) {
			return nil, ErrInvalidRedirect
		}
	}

	return a.oauth.Begin(ctx, providerName, redirectTo)
}

// isValidRedirectURL checks if the URL is safe for redirection
func (a *Auth) isValidRedirectURL(redirectTo string) bool {
	// Parse the redirect URL
	parsed, err := url.Parse(redirectTo)
	if err != nil {
		return false
	}

	// Must be an absolute URL with http or https scheme
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}

	// Check against TrustedOrigins
	redirectOrigin := parsed.Scheme + "://" + parsed.Host

	// BaseURL is always trusted
	baseURL, err := url.Parse(a.config.BaseURL)
	if err == nil {
		baseOrigin := baseURL.Scheme + "://" + baseURL.Host
		if strings.EqualFold(redirectOrigin, baseOrigin) {
			return true
		}
	}

	// Check TrustedOrigins
	for _, trusted := range a.config.TrustedOrigins {
		trustedParsed, err := url.Parse(trusted)
		if err != nil {
			continue
		}
		trustedOrigin := trustedParsed.Scheme + "://" + trustedParsed.Host
		if strings.EqualFold(redirectOrigin, trustedOrigin) {
			return true
		}
	}

	return false
}

// CompleteOAuth completes an OAuth flow and creates/updates user and session
// Returns user, session, redirectTo URL (validated during BeginOAuth), and error
func (a *Auth) CompleteOAuth(ctx context.Context, providerName, code, state string, r *http.Request) (*User, *Session, string, error) {
	if a.oauth == nil {
		return nil, nil, "", ErrOAuthProviderNotFound
	}

	result, oauthState, err := a.oauth.Complete(ctx, providerName, code, state)
	if err != nil {
		return nil, nil, "", err
	}

	provider := ProviderType(providerName)

	// Check if account already exists
	account, err := a.store.GetAccountByProvider(ctx, provider, result.UserInfo.ID)
	if err != nil {
		return nil, nil, "", err
	}

	var user *User
	now := time.Now()

	if account != nil {
		// Existing account - get user
		user, err = a.store.GetUserByID(ctx, account.UserID)
		if err != nil {
			return nil, nil, "", err
		}

		// Update OAuth tokens
		if result.OAuthToken.AccessToken != "" {
			encrypted, err := a.oauth.EncryptToken(result.OAuthToken.AccessToken)
			if err == nil {
				account.AccessToken = &encrypted
			}
		}
		if result.OAuthToken.RefreshToken != "" {
			encrypted, err := a.oauth.EncryptToken(result.OAuthToken.RefreshToken)
			if err == nil {
				account.RefreshToken = &encrypted
			}
		}
		if !result.OAuthToken.Expiry.IsZero() {
			account.AccessTokenExpiresAt = &result.OAuthToken.Expiry
		}
		account.UpdatedAt = now

		if err := a.store.UpdateAccount(ctx, account); err != nil {
			return nil, nil, "", err
		}
	} else {
		// Check if user exists by email
		user, err = a.store.GetUserByEmail(ctx, result.UserInfo.Email)
		if err != nil {
			return nil, nil, "", err
		}

		if user == nil {
			// Create new user
			user = &User{
				ID:            uuid.New().String(),
				Email:         result.UserInfo.Email,
				EmailVerified: result.UserInfo.EmailVerified,
				Name:          result.UserInfo.Name,
				CreatedAt:     now,
				UpdatedAt:     now,
			}
			if result.UserInfo.Picture != "" {
				user.Image = &result.UserInfo.Picture
			}

			if err := a.store.CreateUser(ctx, user); err != nil {
				return nil, nil, "", err
			}

			a.config.Hooks.fireUserCreated(ctx, a.config.Logger, user)
		}

		// Create OAuth account
		providerID := result.UserInfo.ID
		account = &Account{
			ID:                uuid.New().String(),
			UserID:            user.ID,
			Provider:          provider,
			ProviderAccountID: &providerID,
			CreatedAt:         now,
			UpdatedAt:         now,
		}

		// Encrypt and store tokens
		if result.OAuthToken.AccessToken != "" {
			encrypted, err := a.oauth.EncryptToken(result.OAuthToken.AccessToken)
			if err == nil {
				account.AccessToken = &encrypted
			}
		}
		if result.OAuthToken.RefreshToken != "" {
			encrypted, err := a.oauth.EncryptToken(result.OAuthToken.RefreshToken)
			if err == nil {
				account.RefreshToken = &encrypted
			}
		}
		if !result.OAuthToken.Expiry.IsZero() {
			account.AccessTokenExpiresAt = &result.OAuthToken.Expiry
		}

		if err := a.store.CreateAccount(ctx, account); err != nil {
			return nil, nil, "", err
		}

		a.config.Hooks.fireOAuthAccountLinked(ctx, a.config.Logger, user, account)
	}

	// Create session
	session, err := a.createSession(ctx, user.ID, r)
	if err != nil {
		return nil, nil, "", err
	}

	a.config.Hooks.fireSignIn(ctx, a.config.Logger, user, session)

	// Return the validated redirect URL from state (validated during BeginOAuth)
	redirectTo := ""
	if oauthState != nil && oauthState.RedirectTo != nil {
		redirectTo = *oauthState.RedirectTo
	}

	return user, session, redirectTo, nil
}

// oauthStateStore returns a StateStore adapter for the auth store
func (a *Auth) oauthStateStore() oauth.StateStore {
	return &oauthStateStoreAdapter{store: a.store}
}

// oauthStateStoreAdapter adapts the auth Store to oauth.StateStore
type oauthStateStoreAdapter struct {
	store Store
}

func (s *oauthStateStoreAdapter) CreateOAuthState(ctx context.Context, state *oauth.State) error {
	authState := &OAuthState{
		State:      state.State,
		Provider:   state.Provider,
		Verifier:   state.Verifier,
		RedirectTo: state.RedirectTo,
		CreatedAt:  state.CreatedAt,
		ExpiresAt:  state.ExpiresAt,
	}
	return s.store.CreateOAuthState(ctx, authState)
}

func (s *oauthStateStoreAdapter) GetOAuthState(ctx context.Context, stateValue string) (*oauth.State, error) {
	authState, err := s.store.GetOAuthState(ctx, stateValue)
	if err != nil {
		return nil, err
	}
	if authState == nil {
		return nil, nil
	}
	return &oauth.State{
		State:      authState.State,
		Provider:   authState.Provider,
		Verifier:   authState.Verifier,
		RedirectTo: authState.RedirectTo,
		CreatedAt:  authState.CreatedAt,
		ExpiresAt:  authState.ExpiresAt,
	}, nil
}

func (s *oauthStateStoreAdapter) DeleteOAuthState(ctx context.Context, stateValue string) error {
	return s.store.DeleteOAuthState(ctx, stateValue)
}

func (s *oauthStateStoreAdapter) DeleteExpiredOAuthStates(ctx context.Context) error {
	return s.store.DeleteExpiredOAuthStates(ctx)
}
