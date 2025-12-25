// Package auth provides a complete authentication system for Go web applications.
// It supports email/password authentication, OAuth providers (Google, GitHub, Discord),
// session management, CSRF protection, rate limiting, and a plugin system for extensibility.
package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/csrf"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/ratelimit"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/token"
)

// Auth is the main authentication orchestrator
type Auth struct {
	config Config
	store  models.Store

	// Password hasher
	hasher PasswordHasher

	// Token utilities
	tokenHasher    *token.Hasher
	tokenEncryptor *token.Encryptor

	// OAuth service (optional)
	oauth *OAuthService

	// Plugin registry
	plugins *plugin.Registry

	// Cleanup control
	stopCleanup chan struct{}
}

// New creates a new Auth instance.
//
// By default, Auth includes:
//   - Rate limiting (via plugin)
//   - CSRF protection
//   - Session cleanup
//   - Admin endpoints
//
// Use WithoutDefaults() to disable default features and manually Use() plugins.
func New(store models.Store, opts ...Option) (*Auth, error) {
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

	// Create Auth instance
	a := &Auth{
		config:         cfg,
		store:          store,
		hasher:         NewArgon2PasswordHasher(),
		tokenHasher:    token.NewHasher(cfg.Secret),
		tokenEncryptor: token.NewEncryptor(cfg.Secret),
	}

	// Initialize plugin registry
	// Use provided registry or create a new one
	if cfg.Plugins != nil {
		a.plugins = cfg.Plugins
	} else {
		a.plugins = plugin.NewRegistry(cfg.Logger)
	}

	// Register default plugins if not skipping defaults
	if !cfg.SkipDefaults {
		a.registerDefaultPlugins()
	}

	// Initialize plugins with context that includes AuthCore
	pluginCtx := a.buildPluginContext()
	if err := a.plugins.Init(pluginCtx); err != nil {
		return nil, err
	}

	// Merge plugin hooks with config hooks
	a.mergePluginHooks()

	// Start background cleanup if interval is configured and not skipping defaults
	if cfg.SessionCleanupInterval > 0 && !cfg.SkipDefaults {
		a.stopCleanup = make(chan struct{})
		go a.runCleanup()
	}

	return a, nil
}

// registerDefaultPlugins registers the default plugins
func (a *Auth) registerDefaultPlugins() {
	// Rate limiting plugin
	if a.config.RateLimitEnabled {
		var opts []ratelimit.Option
		opts = append(opts, ratelimit.WithLimit(a.config.AuthRateLimitMax, a.config.RateLimitWindow))
		if a.config.RateLimiterBackend != nil {
			opts = append(opts, ratelimit.WithBackend(a.config.RateLimiterBackend))
		}
		if len(a.config.TrustedProxies) > 0 {
			opts = append(opts, ratelimit.WithTrustedProxies(a.config.TrustedProxies))
		}
		a.plugins.Register(ratelimit.NewPlugin(opts...))
	}

	// CSRF protection plugin
	if a.config.CSRFEnabled {
		var opts []csrf.Option
		if a.config.CSRFCookieName != "" {
			opts = append(opts, csrf.WithCookieName(a.config.CSRFCookieName))
		}
		if a.config.CSRFHeaderName != "" {
			opts = append(opts, csrf.WithHeaderName(a.config.CSRFHeaderName))
		}
		a.plugins.Register(csrf.NewPlugin(opts...))
	}

	// Future: Admin plugin, etc.
}

// Close stops background goroutines and cleans up resources
// Should be called when the Auth instance is no longer needed
func (a *Auth) Close() {
	if a.stopCleanup != nil {
		close(a.stopCleanup)
	}
	if a.plugins != nil {
		a.plugins.Close()
	}
}

// mergePluginHooks merges hooks from plugins with config hooks.
// Plugin hooks are chained to run after config hooks.
func (a *Auth) mergePluginHooks() {
	if a.plugins == nil {
		return
	}

	pluginHooks := a.plugins.Hooks()

	// Merge per-event hooks (plugin hooks run after config hooks)
	if pluginHooks.OnUserCreated != nil {
		prev := a.config.Hooks.OnUserCreated
		a.config.Hooks.OnUserCreated = func(ctx context.Context, user *models.User) error {
			if prev != nil {
				if err := prev(ctx, user); err != nil {
					return err
				}
			}
			return pluginHooks.OnUserCreated(ctx, user.ID)
		}
	}

	if pluginHooks.OnSignIn != nil {
		prev := a.config.Hooks.OnSignIn
		a.config.Hooks.OnSignIn = func(ctx context.Context, user *models.User, session *models.Session) error {
			if prev != nil {
				if err := prev(ctx, user, session); err != nil {
					return err
				}
			}
			return pluginHooks.OnSignIn(ctx, user.ID, session.ID)
		}
	}

	if pluginHooks.OnSignOut != nil {
		prev := a.config.Hooks.OnSignOut
		a.config.Hooks.OnSignOut = func(ctx context.Context, user *models.User, session *models.Session) error {
			if prev != nil {
				if err := prev(ctx, user, session); err != nil {
					return err
				}
			}
			return pluginHooks.OnSignOut(ctx, user.ID, session.ID)
		}
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
func (a *Auth) SignUp(ctx context.Context, req SignUpRequest, r *http.Request) (*models.User, *models.Session, error) {
	// Validate password
	if err := a.validatePassword(req.Password); err != nil {
		return nil, nil, err
	}

	// Run plugin validators
	if a.plugins != nil {
		if err := a.plugins.ValidateSignUp(ctx, req.Email, req.Password, req.Name); err != nil {
			return nil, nil, err
		}
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
	user := &models.User{
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
	account := &models.Account{
		ID:           uuid.New().String(),
		UserID:       user.ID,
		Provider:     models.ProviderEmail,
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
	a.config.Hooks.FireUserCreated(ctx, a.config.Logger, user)

	// Auto sign-in if enabled
	var session *models.Session
	if a.config.AutoSignIn {
		session, err = a.createSession(ctx, user.ID, r)
		if err != nil {
			return nil, nil, err
		}
		a.config.Hooks.FireSignIn(ctx, a.config.Logger, user, session)
	}

	return user, session, nil
}

// SignIn authenticates a user with email/password
func (a *Auth) SignIn(ctx context.Context, email, password string, r *http.Request) (*models.User, *models.Session, error) {
	// Run plugin validators before sign in
	if a.plugins != nil {
		if err := a.plugins.ValidateSignIn(ctx, email); err != nil {
			return nil, nil, err
		}
	}

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
	account, err := a.store.GetAccountByUserIDAndProvider(ctx, user.ID, models.ProviderEmail)
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
	a.config.Hooks.FireSignIn(ctx, a.config.Logger, user, session)

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
		a.config.Hooks.FireSignOut(ctx, a.config.Logger, user, session)
	}

	return nil
}

// SignOutAll signs out all sessions for a user
func (a *Auth) SignOutAll(ctx context.Context, userID string) error {
	return a.store.DeleteSessionsByUserID(ctx, userID)
}

// GetUser retrieves a user by ID
func (a *Auth) GetUser(ctx context.Context, userID string) (*models.User, error) {
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
func (a *Auth) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
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
	_ = a.store.DeleteVerificationsByUserIDAndType(ctx, user.ID, models.VerificationTypePasswordReset)

	// Create new token
	rawToken, err := token.Generate()
	if err != nil {
		return err
	}

	tokenHash := a.tokenHasher.Hash(rawToken)
	now := time.Now()

	v := &models.Verification{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		TokenHash: tokenHash,
		Type:      models.VerificationTypePasswordReset,
		ExpiresAt: now.Add(a.config.PasswordResetExpiry),
		CreatedAt: now,
	}

	if err := a.store.CreateVerification(ctx, v); err != nil {
		return err
	}

	// Fire hook with the raw token (for sending email)
	a.config.Hooks.FirePasswordResetRequested(ctx, a.config.Logger, user, rawToken)

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
	if verification.Type != models.VerificationTypePasswordReset {
		return ErrVerificationNotFound
	}
	if verification.IsExpired() {
		_ = a.store.DeleteVerification(ctx, verification.ID)
		return ErrVerificationExpired
	}

	// Get email account
	account, err := a.store.GetAccountByUserIDAndProvider(ctx, verification.UserID, models.ProviderEmail)
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
		a.config.Hooks.FirePasswordChanged(ctx, a.config.Logger, user)
	}

	return nil
}

// ChangePassword changes a user's password (requires current password)
func (a *Auth) ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error {
	if err := a.validatePassword(newPassword); err != nil {
		return err
	}

	// Get email account
	account, err := a.store.GetAccountByUserIDAndProvider(ctx, userID, models.ProviderEmail)
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
		a.config.Hooks.FirePasswordChanged(ctx, a.config.Logger, user)
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
	_ = a.store.DeleteVerificationsByUserIDAndType(ctx, userID, models.VerificationTypeEmail)

	// Create new token
	rawToken, err := token.Generate()
	if err != nil {
		return err
	}

	tokenHash := a.tokenHasher.Hash(rawToken)
	now := time.Now()

	v := &models.Verification{
		ID:        uuid.New().String(),
		UserID:    userID,
		TokenHash: tokenHash,
		Type:      models.VerificationTypeEmail,
		ExpiresAt: now.Add(a.config.EmailVerificationExpiry),
		CreatedAt: now,
	}

	if err := a.store.CreateVerification(ctx, v); err != nil {
		return err
	}

	// Fire hook with the raw token (for sending email)
	a.config.Hooks.FireEmailVerificationRequested(ctx, a.config.Logger, user, rawToken)

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
	if verification.Type != models.VerificationTypeEmail {
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
		a.config.Hooks.FireEmailVerified(ctx, a.config.Logger, user)
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
func (a *Auth) Store() models.Store {
	return a.store
}
