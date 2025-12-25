package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// Ensure Auth implements plugin.AuthCore at compile time
var _ plugin.AuthCore = (*Auth)(nil)

// Use adds a plugin to the auth instance.
// The plugin is immediately initialized and its routes/middleware/hooks are registered.
// This can be called after New() to add optional plugins.
//
// Example:
//
//	auth := betterauth.New(store, betterauth.WithSecret(secret))
//	auth.Use(jwt.Plugin())
//	auth.Use(oauth.Plugin(providers.Google(...)))
func (a *Auth) Use(p plugin.Plugin) error {
	// Ensure we have a plugin registry
	if a.plugins == nil {
		a.plugins = plugin.NewRegistry(a.config.Logger)
		// Initialize the registry with context
		pluginCtx := a.buildPluginContext()
		if err := a.plugins.Init(pluginCtx); err != nil {
			return err
		}
	}

	return a.plugins.AddPlugin(p)
}

// buildPluginContext creates a plugin.Context with access to auth internals
func (a *Auth) buildPluginContext() plugin.Context {
	ctx := plugin.Context{
		BaseURL:   a.config.BaseURL,
		Secret:    a.config.Secret,
		Auth:      a, // Auth implements plugin.AuthCore
		Hasher:    a.tokenHasher,
		Encryptor: a.tokenEncryptor,
	}

	// Check if store provides DB access
	if dbProvider, ok := a.store.(plugin.DBProvider); ok {
		ctx.DB = dbProvider.DB()
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

// ValidateSessionToken validates a session token and returns the session.
// Implements plugin.AuthCore.
func (a *Auth) ValidateSessionToken(ctx context.Context, token string) (*plugin.Session, error) {
	session, err := a.ValidateSession(ctx, token)
	if err != nil {
		return nil, err
	}
	return toPluginSession(session), nil
}

// CreateSessionForUser creates a new session for the given user.
// Implements plugin.AuthCore.
func (a *Auth) CreateSessionForUser(ctx context.Context, userID string, r *http.Request) (*plugin.Session, error) {
	session, err := a.createSession(ctx, userID, r)
	if err != nil {
		return nil, err
	}
	return toPluginSession(session), nil
}

// VerifyPassword verifies a user's password.
// Implements plugin.AuthCore.
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

// GetPluginUser retrieves a user by ID and converts to plugin.User.
// This wraps GetUser to return the plugin-specific type.
func (a *Auth) GetPluginUser(ctx context.Context, userID string) (*plugin.User, error) {
	user, err := a.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	return toPluginUser(user), nil
}

// GetPluginUserByEmail retrieves a user by email and converts to plugin.User.
// This wraps GetUserByEmail to return the plugin-specific type.
func (a *Auth) GetPluginUserByEmail(ctx context.Context, email string) (*plugin.User, error) {
	user, err := a.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	return toPluginUser(user), nil
}

// CreatePluginUser creates a new user from a plugin request.
// This is used by OAuth and other plugins that need to create users without passwords.
// Implements plugin.AuthCore.
func (a *Auth) CreatePluginUser(ctx context.Context, req plugin.CreateUserRequest) (*plugin.User, error) {
	// Check if user already exists
	existing, err := a.store.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, ErrUserAlreadyExists
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

	// Fire hook
	a.config.Hooks.FireUserCreated(ctx, a.config.Logger, user)

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

// FireOAuthAccountLinked fires the OnOAuthAccountLinked hook.
// This calls both the core hooks (using models types) and plugin hooks (using simple IDs).
// Implements plugin.AuthCore.
func (a *Auth) FireOAuthAccountLinked(ctx context.Context, userID, provider, providerAccountID string) error {
	// Fire plugin hooks first (simple ID-based)
	if a.plugins != nil {
		pluginHooks := a.plugins.Hooks()
		if pluginHooks.OnOAuthAccountLinked != nil {
			if err := pluginHooks.OnOAuthAccountLinked(ctx, userID, provider, providerAccountID); err != nil {
				a.config.Logger.Warn("plugin hook failed", "hook", "OnOAuthAccountLinked", "error", err)
			}
		}
	}

	// Fire core hook (needs user and account models)
	user, err := a.store.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	account := &models.Account{
		UserID:            userID,
		Provider:          models.ProviderType(provider),
		ProviderAccountID: &providerAccountID,
	}

	a.config.Hooks.FireOAuthAccountLinked(ctx, a.config.Logger, user, account)

	return nil
}

// toPluginSession converts a models.Session to plugin.Session
func toPluginSession(s *models.Session) *plugin.Session {
	if s == nil {
		return nil
	}
	return &plugin.Session{
		ID:        s.ID,
		UserID:    s.UserID,
		IPAddress: s.IPAddress,
		UserAgent: s.UserAgent,
		CreatedAt: s.CreatedAt,
		ExpiresAt: s.ExpiresAt,
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

// SkipDefaults returns whether default features are disabled.
func (a *Auth) SkipDefaults() bool {
	return a.config.SkipDefaults
}
