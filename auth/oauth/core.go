// Package oauth provides OAuth 2.0 authentication integration for the auth server.
// It handles OAuth provider configuration, user account linking, and authentication flows.
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/token"
	"golang.org/x/oauth2"
)

// StateStore defines the interface for storing OAuth state
type StateStore interface {
	CreateOAuthState(ctx context.Context, state *State) error
	GetOAuthState(ctx context.Context, stateValue string) (*State, error)
	DeleteOAuthState(ctx context.Context, stateValue string) error
	DeleteExpiredOAuthStates(ctx context.Context) error
}

// State represents an OAuth state record
type State struct {
	State      string
	Provider   string
	Verifier   *string
	RedirectTo *string
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// IsExpired returns true if the state has expired
func (s *State) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// OAuthAccount represents an OAuth account linked to a user.
// This stores the provider-specific tokens and identifiers.
type OAuthAccount struct {
	ID                   string
	UserID               string
	Provider             string
	ProviderAccountID    string
	AccessToken          string
	RefreshToken         string
	AccessTokenExpiresAt *time.Time
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// Service handles OAuth authentication flows
type Service struct {
	providers  map[string]Provider
	stateStore StateStore
	hasher     *token.Hasher
	encryptor  *token.Encryptor
	stateTTL   time.Duration
}

// NewService creates a new OAuth service
func NewService(stateStore StateStore, hasher *token.Hasher, encryptor *token.Encryptor) *Service {
	return &Service{
		providers:  make(map[string]Provider),
		stateStore: stateStore,
		hasher:     hasher,
		encryptor:  encryptor,
		stateTTL:   10 * time.Minute,
	}
}

// RegisterProvider registers an OAuth provider
func (s *Service) RegisterProvider(p Provider) {
	s.providers[p.Name()] = p
}

// GetProvider returns a provider by name
func (s *Service) GetProvider(name string) (Provider, bool) {
	p, ok := s.providers[name]
	return p, ok
}

// ListProviders returns the names of all registered providers
func (s *Service) ListProviders() []string {
	names := make([]string, 0, len(s.providers))
	for name := range s.providers {
		names = append(names, name)
	}
	return names
}

// Begin starts an OAuth flow for the given provider
func (s *Service) Begin(ctx context.Context, providerName string, redirectTo string) (*AuthStart, error) {
	provider, ok := s.providers[providerName]
	if !ok {
		return nil, ErrProviderNotFound
	}

	// Generate state
	stateValue, err := generateRandomString(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	var verifier string
	var authURL string

	if provider.RequiresPKCE() {
		// Generate PKCE verifier and challenge
		verifier, err = generateRandomString(64)
		if err != nil {
			return nil, fmt.Errorf("failed to generate verifier: %w", err)
		}

		challenge := generateCodeChallenge(verifier)
		authURL = provider.Config().AuthCodeURL(stateValue,
			oauth2.SetAuthURLParam("code_challenge", challenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		)
	} else {
		authURL = provider.Config().AuthCodeURL(stateValue)
	}

	// Store state
	now := time.Now()
	state := &State{
		State:     stateValue,
		Provider:  providerName,
		CreatedAt: now,
		ExpiresAt: now.Add(s.stateTTL),
	}

	if verifier != "" {
		state.Verifier = &verifier
	}
	if redirectTo != "" {
		state.RedirectTo = &redirectTo
	}

	if err := s.stateStore.CreateOAuthState(ctx, state); err != nil {
		return nil, fmt.Errorf("failed to store state: %w", err)
	}

	return &AuthStart{
		URL:      authURL,
		State:    stateValue,
		Verifier: verifier,
	}, nil
}

// Complete completes an OAuth flow
func (s *Service) Complete(ctx context.Context, providerName, code, stateValue string) (*AuthResult, *State, error) {
	provider, ok := s.providers[providerName]
	if !ok {
		return nil, nil, ErrProviderNotFound
	}

	// Retrieve and validate state
	state, err := s.stateStore.GetOAuthState(ctx, stateValue)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get state: %w", err)
	}
	if state == nil {
		return nil, nil, ErrStateNotFound
	}

	// Constant-time comparison
	if subtle.ConstantTimeCompare([]byte(state.Provider), []byte(providerName)) != 1 {
		return nil, nil, ErrStateMismatch
	}

	if state.IsExpired() {
		_ = s.stateStore.DeleteOAuthState(ctx, stateValue)
		return nil, nil, ErrStateExpired
	}

	// Exchange code for token
	var token *oauth2.Token
	if state.Verifier != nil {
		token, err = provider.Config().Exchange(ctx, code,
			oauth2.SetAuthURLParam("code_verifier", *state.Verifier),
		)
	} else {
		token, err = provider.Config().Exchange(ctx, code)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	// Get user info
	userInfo, err := provider.GetUserInfo(ctx, token)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Delete used state
	_ = s.stateStore.DeleteOAuthState(ctx, stateValue)

	return &AuthResult{
		UserInfo:   userInfo,
		OAuthToken: token,
	}, state, nil
}

// EncryptToken encrypts an OAuth token for storage
func (s *Service) EncryptToken(tokenValue string) (string, error) {
	return s.encryptor.Encrypt(tokenValue)
}

// DecryptToken decrypts a stored OAuth token
func (s *Service) DecryptToken(encrypted string) (string, error) {
	return s.encryptor.Decrypt(encrypted)
}

// generateRandomString generates a random URL-safe string
func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

// generateCodeChallenge generates a PKCE code challenge from a verifier
func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
