// Package auth provides a complete authentication system for Go web applications.
// It supports email/password authentication, OAuth providers (Google, GitHub, Discord),
// session management, CSRF protection, rate limiting, and a plugin system for extensibility.
package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/config"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/defaults"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/events"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/token"
)

// Auth is the main authentication orchestrator
type Auth struct {
	config *config.Config
	store  models.Store

	// Password hasher
	hasher models.PasswordHasher

	// Token utilities
	tokenHasher    *token.Hasher
	tokenEncryptor *token.Encryptor

	// Event bus for publishing auth events
	eventBus models.EventBus

	// Plugin registry
	plugins *plugin.Registry

	// Cleanup control
	stopCleanup chan struct{}

	// initErr stores any error from post-construction operations like Use()
	initErr error
}

// New creates a new Auth instance.
//
// By default, no plugins are registered. Use config.WithDefaults() to enable
// the standard plugin bundle which includes (based on your config):
//   - OTP (for password reset and email verification)
//   - Password authentication
//   - Rate limiting
//   - CSRF protection
//   - Session cleanup
//
// Or use Use() to register individual plugins for fine-grained control.
func New(store models.Store, opts ...config.Option) (*Auth, error) {
	cfg := config.NewConfig(opts...)

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	if store == nil {
		return nil, models.ErrMissingStore
	}

	// Create default EventBus if not provided
	if cfg.EventBus == nil {
		cfg.EventBus = events.Default(cfg.Logger)
	}

	// Create Auth instance
	a := &Auth{
		config:         cfg,
		store:          store,
		hasher:         models.NewArgon2PasswordHasher(),
		tokenHasher:    token.NewHasher(cfg.Secret),
		tokenEncryptor: token.NewEncryptor(cfg.Secret),
		eventBus:       cfg.EventBus,
	}

	// Initialize plugin registry
	// Use provided registry or create a new one
	if cfg.Plugins != nil {
		a.plugins = cfg.Plugins
	} else {
		a.plugins = plugin.NewRegistry(cfg.Logger)
	}

	// Register default plugins if explicitly enabled
	if cfg.UseDefaults {
		for _, p := range defaults.Plugins(cfg) {
			a.plugins.Register(p)
		}
	}

	// Initialize plugins with context that includes AuthCore
	pluginCtx := a.buildPluginContext()
	if err := a.plugins.Init(pluginCtx); err != nil {
		return nil, err
	}

	// Start background cleanup if interval is configured and defaults are enabled
	if cfg.SessionCleanupInterval > 0 && cfg.UseDefaults {
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
	if a.plugins != nil {
		_ = a.plugins.Close()
	}
	if a.eventBus != nil {
		_ = a.eventBus.Close()
	}
}

// EventBus returns the event bus for subscribing to auth events.
// Use this to add custom handlers for events like user creation, sign-in, etc.
func (a *Auth) EventBus() models.EventBus {
	return a.eventBus
}

// publishEvent publishes an event to the event bus.
// Errors are logged but not returned since events are fire-and-forget.
func (a *Auth) publishEvent(ctx context.Context, eventType string, payload any) {
	if a.eventBus == nil {
		return
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		a.config.Logger.Error("failed to marshal event payload", "event", eventType, "error", err)
		return
	}

	event := models.Event{
		Type:    eventType,
		Payload: payloadBytes,
	}

	if err := a.eventBus.Publish(ctx, event); err != nil {
		a.config.Logger.Error("failed to publish event", "event", eventType, "error", err)
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

			a.config.Logger.Debug("completed cleanup of expired data")
		}
	}
}

// SignOut signs out the current session
func (a *Auth) SignOut(ctx context.Context, sessionID string) error {
	session, err := a.store.GetSessionByID(ctx, sessionID)
	if err != nil {
		return err
	}
	if session == nil {
		return models.ErrSessionNotFound
	}

	user, err := a.store.GetUserByID(ctx, session.UserID)
	if err != nil {
		return err
	}

	if err := a.store.DeleteSession(ctx, sessionID); err != nil {
		return err
	}

	// Publish signed out event
	if user != nil {
		a.publishEvent(ctx, models.EventSignedOut, models.SignedOutPayload{User: user, Session: session})
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
		return nil, models.ErrUserNotFound
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
		return nil, models.ErrUserNotFound
	}
	return user, nil
}

// SendVerificationEmail sends an email verification token
func (a *Auth) SendVerificationEmail(ctx context.Context, userID string) error {
	user, err := a.store.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return models.ErrUserNotFound
	}
	if user.EmailVerified {
		return models.ErrEmailAlreadyVerified
	}

	provider := a.emailVerificationProvider()
	if provider == nil {
		return models.ErrEmailVerificationNotAvailable
	}

	rawToken, err := provider.CreateEmailVerificationToken(ctx, userID)
	if err != nil {
		return err
	}

	a.publishEvent(ctx, models.EventEmailVerificationSent, models.EmailVerificationSentPayload{User: user, Token: rawToken})
	return nil
}

// VerifyEmail verifies a user's email with the provided token
func (a *Auth) VerifyEmail(ctx context.Context, rawToken string) error {
	provider := a.emailVerificationProvider()
	if provider == nil {
		return models.ErrEmailVerificationNotAvailable
	}

	userID, err := provider.ConsumeEmailVerificationToken(ctx, rawToken)
	if err != nil {
		return err
	}

	if err := a.store.SetEmailVerified(ctx, userID, true); err != nil {
		return err
	}

	user, _ := a.store.GetUserByID(ctx, userID)
	if user != nil {
		a.publishEvent(ctx, models.EventEmailVerified, models.EmailVerifiedPayload{User: user})
	}

	return nil
}

// Config returns the auth configuration (read-only access)
func (a *Auth) Config() *config.Config {
	return a.config
}

// Store returns the store interface
func (a *Auth) Store() models.Store {
	return a.store
}

// emailVerificationProvider finds a plugin that implements EmailVerificationProvider.
// Returns nil if no such plugin is registered.
func (a *Auth) emailVerificationProvider() plugin.EmailVerificationProvider {
	if a.plugins == nil {
		return nil
	}
	for _, p := range a.plugins.Plugins() {
		if provider, ok := p.(plugin.EmailVerificationProvider); ok {
			return provider
		}
	}
	return nil
}

// =============================================================================
// Plugin Integration
// =============================================================================

// Ensure Auth implements plugin.AuthCore at compile time
var _ plugin.AuthCore = (*Auth)(nil)

// Use registers one or more plugins with the auth instance.
// Returns *Auth for method chaining. Check Err() after chaining to detect errors.
//
// Example:
//
//	auth := betterauth.New(store, betterauth.WithSecret(secret))
//	auth.
//		Use(jwt.Plugin()).
//		Use(oauth.Plugin(providers.Google(...))).
//		Use(admin.Plugin(), ratelimit.Plugin())
//
//	if err := auth.Err(); err != nil {
//		log.Fatal("Failed to register plugins:", err)
//	}
func (a *Auth) Use(plugins ...plugin.Plugin) *Auth {
	// Short-circuit if we already have an error
	if a.initErr != nil {
		return a
	}

	// Ensure we have a plugin registry
	if a.plugins == nil {
		a.plugins = plugin.NewRegistry(a.config.Logger)
		// Initialize the registry with context
		pluginCtx := a.buildPluginContext()
		if err := a.plugins.Init(pluginCtx); err != nil {
			a.initErr = err
			return a
		}
	}

	// Register each plugin
	for _, p := range plugins {
		if err := a.plugins.AddPlugin(p); err != nil {
			a.initErr = err
			return a
		}
	}

	return a
}

// Err returns any error that occurred during plugin registration.
// Should be called after chaining Use() calls to check for errors.
func (a *Auth) Err() error {
	return a.initErr
}

// buildPluginContext creates a plugin.Context with access to auth internals
func (a *Auth) buildPluginContext() plugin.Context {
	ctx := plugin.Context{
		BaseURL:   a.config.BaseURL,
		Secret:    a.config.Secret,
		Auth:      a, // Auth implements plugin.AuthCore
		Sessions:  &sessionManager{auth: a},
		Hasher:    a.tokenHasher,
		Encryptor: a.tokenEncryptor,
		Logger:    a.config.Logger,
		EventBus:  a.eventBus,
	}

	// Check if store provides the new PluginStore interface (preferred)
	if storeProvider, ok := a.store.(plugin.PluginStoreProvider); ok {
		ctx.Store = storeProvider.PluginStore()
	}

	// Check if store provides raw DB access
	if dbProvider, ok := a.store.(plugin.DBProvider); ok {
		ctx.RawDB = dbProvider.DB()
		ctx.Dialect = dbProvider.Dialect()
	}

	return ctx
}

// BaseURL returns the base URL configured for the auth service.
// Implements plugin.AuthCore.
func (a *Auth) BaseURL() string {
	return a.config.BaseURL
}

// Secret returns the secret key.
// Implements plugin.AuthCore.
func (a *Auth) Secret() string {
	return a.config.Secret
}

// CreateSessionForUser creates a new session for the given user.
// Implements jwt.AuthProvider and oauth.AuthProvider.
func (a *Auth) CreateSessionForUser(ctx context.Context, userID string, r *http.Request) (*plugin.Session, error) {
	session, err := a.createSession(ctx, userID, r)
	if err != nil {
		return nil, err
	}
	return toPluginSession(session), nil
}

// VerifyPassword verifies a user's password.
// Implements jwt.AuthProvider.
func (a *Auth) VerifyPassword(ctx context.Context, userID string, password string) (bool, error) {
	account, err := a.store.GetAccountByUserIDAndProvider(ctx, userID, models.ProviderEmail)
	if err != nil {
		return false, err
	}
	if account == nil || account.PasswordHash == nil {
		return false, nil
	}
	return a.hasher.Verify(password, *account.PasswordHash), nil
}

// GetUserFromRequest retrieves the authenticated user from the request context.
// Implements admin.UserProvider.
func (a *Auth) GetUserFromRequest(r *http.Request) (*plugin.User, error) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		return nil, models.ErrForbidden
	}
	return toPluginUser(user), nil
}

// GetSessionFromRequest retrieves the session from the request context.
// Implements password.SessionGetter.
func (a *Auth) GetSessionFromRequest(r *http.Request) *plugin.SessionInfo {
	session := SessionFromContext(r.Context())
	if session == nil {
		return nil
	}
	return &plugin.SessionInfo{
		ID:     session.ID,
		UserID: session.UserID,
	}
}

// GetPlugin returns a plugin by name from the registry.
func (a *Auth) GetPlugin(name string) plugin.Plugin {
	if a.plugins == nil {
		return nil
	}
	return a.plugins.Get(name)
}

// GetPlugins returns all registered plugins.
// Implements password.pluginRegistryGetter.
func (a *Auth) GetPlugins() []plugin.Plugin {
	if a.plugins == nil {
		return nil
	}
	return a.plugins.Plugins()
}

// GetPluginUser retrieves a user by ID and converts to plugin.User.
// Implements jwt.AuthProvider and oauth.AuthProvider.
func (a *Auth) GetPluginUser(ctx context.Context, userID string) (*plugin.User, error) {
	user, err := a.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	return toPluginUser(user), nil
}

// GetPluginUserByEmail retrieves a user by email and converts to plugin.User.
// Implements jwt.AuthProvider and oauth.AuthProvider.
func (a *Auth) GetPluginUserByEmail(ctx context.Context, email string) (*plugin.User, error) {
	user, err := a.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	return toPluginUser(user), nil
}

// CreatePluginUser creates a new user from a plugin request.
// This is used by OAuth and other plugins that need to create users without passwords.
// Implements oauth.AuthProvider.
func (a *Auth) CreatePluginUser(ctx context.Context, req plugin.CreateUserRequest) (*plugin.User, error) {
	// Check if user already exists
	existing, err := a.store.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, models.ErrUserAlreadyExists
	}

	now := time.Now()

	// Create user
	user := &models.User{
		ID:            uuid.New().String(),
		Email:         req.Email,
		Name:          req.Name,
		EmailVerified: req.EmailVerified,
		Image:         req.Image,
		Role:          "user",
		Banned:        false,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if err := a.store.CreateUser(ctx, user); err != nil {
		return nil, err
	}

	// Publish user created event
	a.publishEvent(ctx, models.EventUserCreated, models.UserCreatedPayload{User: user})

	return toPluginUser(user), nil
}

// toPluginUser converts a models.User to plugin.User
func toPluginUser(u *models.User) *plugin.User {
	if u == nil {
		return nil
	}
	return &plugin.User{
		ID:            u.ID,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Name:          u.Name,
		Image:         u.Image,
		Role:          u.Role,
		Banned:        u.Banned,
		CreatedAt:     u.CreatedAt,
		UpdatedAt:     u.UpdatedAt,
	}
}

// DeleteUser deletes a user by ID.
// Implements anonymous.AuthProvider.
func (a *Auth) DeleteUser(ctx context.Context, userID string) error {
	return a.store.DeleteUser(ctx, userID)
}

// FireOAuthAccountLinked publishes an OAuth account linked event.
// Implements oauth.AuthProvider.
func (a *Auth) FireOAuthAccountLinked(ctx context.Context, userID, provider, providerAccountID string) error {
	user, err := a.store.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	account := &models.Account{
		UserID:            userID,
		Provider:          models.ProviderType(provider),
		ProviderAccountID: &providerAccountID,
	}

	a.publishEvent(ctx, models.EventOAuthAccountLinked, models.OAuthAccountLinkedPayload{User: user, Account: account})

	return nil
}

// toPluginSession converts a models.Session to plugin.Session
func toPluginSession(s *models.Session) *plugin.Session {
	if s == nil {
		return nil
	}
	return &plugin.Session{
		ID:             s.ID,
		UserID:         s.UserID,
		IPAddress:      s.IPAddress,
		UserAgent:      s.UserAgent,
		CreatedAt:      s.CreatedAt,
		ExpiresAt:      s.ExpiresAt,
		ImpersonatedBy: s.ImpersonatedBy,
		RawToken:       s.RawToken,
	}
}

// PluginRoutes returns all routes registered by plugins.
// Used by the router to mount plugin-provided endpoints.
func (a *Auth) PluginRoutes() []plugin.Route {
	if a.plugins == nil {
		return nil
	}
	return a.plugins.Routes()
}

// PluginMiddleware returns all middleware registered by plugins, sorted by priority.
// Used by the router to apply plugin-provided middleware.
func (a *Auth) PluginMiddleware() []plugin.Middleware {
	if a.plugins == nil {
		return nil
	}
	return a.plugins.Middleware()
}

// ChainPluginMiddleware applies all plugin middleware to a handler.
func (a *Auth) ChainPluginMiddleware(h http.Handler) http.Handler {
	if a.plugins == nil {
		return h
	}
	return a.plugins.ChainMiddleware(h)
}

// UseDefaults returns whether default features are enabled.
func (a *Auth) UseDefaults() bool {
	return a.config.UseDefaults
}
