// Package auth provides a complete authentication system for Go web applications.
// It supports email/password authentication, OAuth providers (Google, GitHub, Discord),
// session management, CSRF protection, rate limiting, and a plugin system for extensibility.
package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/token"
)

// Auth is the main authentication orchestrator
type Auth struct {
	config Config
	store  Store

	// Password hasher
	hasher PasswordHasher

	// Token utilities
	tokenHasher    *token.Hasher
	tokenEncryptor *token.Encryptor

	// Rate limiter
	rateLimiter *RateLimiter

	// OAuth service (optional)
	oauth *OAuthService

	// Cleanup control
	stopCleanup chan struct{}
}

// New creates a new Auth instance
func New(store Store, opts ...Option) (*Auth, error) {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	if store == nil {
		return nil, ErrMissingStore
	}

	// Create rate limiter if enabled
	var rateLimiter *RateLimiter
	if cfg.RateLimitEnabled {
		rateLimiter = NewRateLimiter(RateLimitConfig{
			Window:          cfg.RateLimitWindow,
			MaxRequests:     cfg.AuthRateLimitMax,
			CleanupInterval: 5 * time.Minute,
		})
	}

	a := &Auth{
		config:         cfg,
		store:          store,
		hasher:         NewArgon2PasswordHasher(),
		tokenHasher:    token.NewHasher(cfg.Secret),
		tokenEncryptor: token.NewEncryptor(cfg.Secret),
		rateLimiter:    rateLimiter,
	}

	// Start background cleanup if interval is configured
	if cfg.SessionCleanupInterval > 0 {
		a.stopCleanup = make(chan struct{})
		go a.runCleanup()
	}

	return a, nil
}

// Close stops background goroutines and cleans up resources
// Should be called when the Auth instance is no longer needed
func (a *Auth) Close() {
	if a.stopCleanup != nil {
		close(a.stopCleanup)
	}
	if a.rateLimiter != nil {
		a.rateLimiter.Close()
	}
}

// runCleanup periodically cleans up expired sessions, verifications, and OAuth states
func (a *Auth) runCleanup() {
	ticker := time.NewTicker(a.config.SessionCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-a.stopCleanup:
			return
		case <-ticker.C:
			ctx := context.Background()

			// Clean up expired sessions
			if err := a.store.DeleteExpiredSessions(ctx); err != nil {
				a.config.Logger.Error("failed to cleanup expired sessions", "error", err)
			}

			// Clean up expired verifications
			if err := a.store.DeleteExpiredVerifications(ctx); err != nil {
				a.config.Logger.Error("failed to cleanup expired verifications", "error", err)
			}

			// Clean up expired OAuth states
			if err := a.store.DeleteExpiredOAuthStates(ctx); err != nil {
				a.config.Logger.Error("failed to cleanup expired oauth states", "error", err)
			}

			a.config.Logger.Debug("completed cleanup of expired data")
		}
	}
}

// SignUpRequest contains the data needed to sign up a new user
type SignUpRequest struct {
	Email    string
	Password string
	Name     string
}

// SignUp creates a new user with email/password authentication
func (a *Auth) SignUp(ctx context.Context, req SignUpRequest, r *http.Request) (*User, *Session, error) {
	// Validate password
	if err := a.validatePassword(req.Password); err != nil {
		return nil, nil, err
	}

	// Check if user already exists
	existing, err := a.store.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, nil, err
	}
	if existing != nil {
		return nil, nil, ErrUserAlreadyExists
	}

	// Hash password
	passwordHash, err := a.hasher.Hash(req.Password)
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()

	// Create user
	user := &User{
		ID:            uuid.New().String(),
		Email:         req.Email,
		Name:          req.Name,
		EmailVerified: false,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := a.store.CreateUser(ctx, user); err != nil {
		return nil, nil, err
	}

	// Create email account
	account := &Account{
		ID:           uuid.New().String(),
		UserID:       user.ID,
		Provider:     ProviderEmail,
		PasswordHash: &passwordHash,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := a.store.CreateAccount(ctx, account); err != nil {
		// Rollback user creation
		_ = a.store.DeleteUser(ctx, user.ID)
		return nil, nil, err
	}

	// Fire hook
	a.config.Hooks.fireUserCreated(ctx, a.config.Logger, user)

	// Auto sign-in if enabled
	var session *Session
	if a.config.AutoSignIn {
		session, err = a.createSession(ctx, user.ID, r)
		if err != nil {
			return nil, nil, err
		}
		a.config.Hooks.fireSignIn(ctx, a.config.Logger, user, session)
	}

	return user, session, nil
}

// SignIn authenticates a user with email/password
func (a *Auth) SignIn(ctx context.Context, email, password string, r *http.Request) (*User, *Session, error) {
	// Get user
	user, err := a.store.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, nil, err
	}
	if user == nil {
		// Prevent user enumeration - still hash the password
		_, _ = a.hasher.Hash(password)
		return nil, nil, ErrInvalidCredentials
	}

	// Get email account
	account, err := a.store.GetAccountByUserIDAndProvider(ctx, user.ID, ProviderEmail)
	if err != nil {
		return nil, nil, err
	}
	if account == nil || account.PasswordHash == nil {
		return nil, nil, ErrInvalidCredentials
	}

	// Verify password
	if !a.hasher.Verify(password, *account.PasswordHash) {
		return nil, nil, ErrInvalidCredentials
	}

	// Create session
	session, err := a.createSession(ctx, user.ID, r)
	if err != nil {
		return nil, nil, err
	}

	// Fire hook
	a.config.Hooks.fireSignIn(ctx, a.config.Logger, user, session)

	return user, session, nil
}

// SignOut signs out the current session
func (a *Auth) SignOut(ctx context.Context, sessionID string) error {
	session, err := a.store.GetSessionByID(ctx, sessionID)
	if err != nil {
		return err
	}
	if session == nil {
		return ErrSessionNotFound
	}

	user, err := a.store.GetUserByID(ctx, session.UserID)
	if err != nil {
		return err
	}

	if err := a.store.DeleteSession(ctx, sessionID); err != nil {
		return err
	}

	// Fire hook
	if user != nil {
		a.config.Hooks.fireSignOut(ctx, a.config.Logger, user, session)
	}

	return nil
}

// SignOutAll signs out all sessions for a user
func (a *Auth) SignOutAll(ctx context.Context, userID string) error {
	return a.store.DeleteSessionsByUserID(ctx, userID)
}

// GetUser retrieves a user by ID
func (a *Auth) GetUser(ctx context.Context, userID string) (*User, error) {
	user, err := a.store.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}
	return user, nil
}

// GetUserByEmail retrieves a user by email
func (a *Auth) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	user, err := a.store.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}
	return user, nil
}

// RequestPasswordReset initiates a password reset flow
func (a *Auth) RequestPasswordReset(ctx context.Context, email string) error {
	user, err := a.store.GetUserByEmail(ctx, email)
	if err != nil {
		return err
	}
	if user == nil {
		// Don't reveal if user exists
		return nil
	}

	// Delete any existing password reset tokens
	_ = a.store.DeleteVerificationsByUserIDAndType(ctx, user.ID, VerificationTypePasswordReset)

	// Create new token
	rawToken, err := token.Generate()
	if err != nil {
		return err
	}

	tokenHash := a.tokenHasher.Hash(rawToken)
	now := time.Now()

	v := &Verification{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		TokenHash: tokenHash,
		Type:      VerificationTypePasswordReset,
		ExpiresAt: now.Add(a.config.PasswordResetExpiry),
		CreatedAt: now,
	}

	if err := a.store.CreateVerification(ctx, v); err != nil {
		return err
	}

	// Fire hook with the raw token (for sending email)
	a.config.Hooks.firePasswordResetRequested(ctx, a.config.Logger, user, rawToken)

	return nil
}

// ConfirmPasswordReset completes a password reset
func (a *Auth) ConfirmPasswordReset(ctx context.Context, rawToken, newPassword string) error {
	if err := a.validatePassword(newPassword); err != nil {
		return err
	}

	tokenHash := a.tokenHasher.Hash(rawToken)

	verification, err := a.store.GetVerificationByTokenHash(ctx, tokenHash)
	if err != nil {
		return err
	}
	if verification == nil {
		return ErrVerificationNotFound
	}
	if verification.Type != VerificationTypePasswordReset {
		return ErrVerificationNotFound
	}
	if verification.IsExpired() {
		_ = a.store.DeleteVerification(ctx, verification.ID)
		return ErrVerificationExpired
	}

	// Get email account
	account, err := a.store.GetAccountByUserIDAndProvider(ctx, verification.UserID, ProviderEmail)
	if err != nil {
		return err
	}
	if account == nil {
		return ErrAccountNotFound
	}

	// Hash new password
	passwordHash, err := a.hasher.Hash(newPassword)
	if err != nil {
		return err
	}

	// Update password
	account.PasswordHash = &passwordHash
	account.UpdatedAt = time.Now()
	if err := a.store.UpdateAccount(ctx, account); err != nil {
		return err
	}

	// Delete the verification token
	_ = a.store.DeleteVerification(ctx, verification.ID)

	// Invalidate all sessions for security
	_ = a.store.DeleteSessionsByUserID(ctx, verification.UserID)

	// Fire hook
	user, _ := a.store.GetUserByID(ctx, verification.UserID)
	if user != nil {
		a.config.Hooks.firePasswordChanged(ctx, a.config.Logger, user)
	}

	return nil
}

// ChangePassword changes a user's password (requires current password)
func (a *Auth) ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error {
	if err := a.validatePassword(newPassword); err != nil {
		return err
	}

	// Get email account
	account, err := a.store.GetAccountByUserIDAndProvider(ctx, userID, ProviderEmail)
	if err != nil {
		return err
	}
	if account == nil || account.PasswordHash == nil {
		return ErrAccountNotFound
	}

	// Verify old password
	if !a.hasher.Verify(oldPassword, *account.PasswordHash) {
		return ErrInvalidCredentials
	}

	// Hash new password
	passwordHash, err := a.hasher.Hash(newPassword)
	if err != nil {
		return err
	}

	// Update password
	account.PasswordHash = &passwordHash
	account.UpdatedAt = time.Now()
	if err := a.store.UpdateAccount(ctx, account); err != nil {
		return err
	}

	// Invalidate all sessions for security
	_ = a.store.DeleteSessionsByUserID(ctx, userID)

	// Fire hook
	user, _ := a.store.GetUserByID(ctx, userID)
	if user != nil {
		a.config.Hooks.firePasswordChanged(ctx, a.config.Logger, user)
	}

	return nil
}

// SendVerificationEmail sends an email verification token
func (a *Auth) SendVerificationEmail(ctx context.Context, userID string) error {
	user, err := a.store.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}
	if user.EmailVerified {
		return ErrEmailAlreadyVerified
	}

	// Delete any existing email verification tokens
	_ = a.store.DeleteVerificationsByUserIDAndType(ctx, userID, VerificationTypeEmail)

	// Create new token
	rawToken, err := token.Generate()
	if err != nil {
		return err
	}

	tokenHash := a.tokenHasher.Hash(rawToken)
	now := time.Now()

	v := &Verification{
		ID:        uuid.New().String(),
		UserID:    userID,
		TokenHash: tokenHash,
		Type:      VerificationTypeEmail,
		ExpiresAt: now.Add(a.config.EmailVerificationExpiry),
		CreatedAt: now,
	}

	if err := a.store.CreateVerification(ctx, v); err != nil {
		return err
	}

	// Fire hook with the raw token (for sending email)
	a.config.Hooks.fireEmailVerificationRequested(ctx, a.config.Logger, user, rawToken)

	return nil
}

// VerifyEmail verifies a user's email with the provided token
func (a *Auth) VerifyEmail(ctx context.Context, rawToken string) error {
	tokenHash := a.tokenHasher.Hash(rawToken)

	verification, err := a.store.GetVerificationByTokenHash(ctx, tokenHash)
	if err != nil {
		return err
	}
	if verification == nil {
		return ErrVerificationNotFound
	}
	if verification.Type != VerificationTypeEmail {
		return ErrVerificationNotFound
	}
	if verification.IsExpired() {
		_ = a.store.DeleteVerification(ctx, verification.ID)
		return ErrVerificationExpired
	}

	if err := a.store.SetEmailVerified(ctx, verification.UserID, true); err != nil {
		return err
	}

	// Delete the verification token
	_ = a.store.DeleteVerification(ctx, verification.ID)

	// Fire hook
	user, _ := a.store.GetUserByID(ctx, verification.UserID)
	if user != nil {
		a.config.Hooks.fireEmailVerified(ctx, a.config.Logger, user)
	}

	return nil
}

// validatePassword checks if a password meets the requirements
func (a *Auth) validatePassword(password string) error {
	if len(password) < a.config.PasswordMinLength {
		return ErrPasswordTooShort
	}
	if len(password) > a.config.PasswordMaxLength {
		return ErrPasswordTooLong
	}

	// Check complexity requirements if enabled
	if a.config.RequirePasswordComplexity {
		var hasUpper, hasLower, hasDigit, hasSpecial bool
		for _, c := range password {
			switch {
			case c >= 'A' && c <= 'Z':
				hasUpper = true
			case c >= 'a' && c <= 'z':
				hasLower = true
			case c >= '0' && c <= '9':
				hasDigit = true
			case isSpecialChar(c):
				hasSpecial = true
			}
		}
		if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
			return ErrPasswordTooWeak
		}
	}

	return nil
}

// isSpecialChar returns true if the rune is a special character
func isSpecialChar(c rune) bool {
	specialChars := "!@#$%^&*()_+-=[]{}|;':\",./<>?`~"
	for _, s := range specialChars {
		if c == s {
			return true
		}
	}
	return false
}

// Config returns the auth configuration (read-only access)
func (a *Auth) Config() Config {
	return a.config
}

// Store returns the store interface
func (a *Auth) Store() Store {
	return a.store
}
