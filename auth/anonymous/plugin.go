package anonymous

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

const (
	PluginName = "anonymous"

	// MiddlewarePriority runs before auth handlers to capture previous session
	MiddlewarePriority = 5
)

// Plugin provides anonymous authentication functionality
type Plugin struct {
	ctx     plugin.Context
	auth    AuthProvider
	service *Service
	opts    []Option
}

// Compile-time interface checks
var (
	_ plugin.Plugin             = (*Plugin)(nil)
	_ plugin.RoutesProvider     = (*Plugin)(nil)
	_ plugin.MiddlewareProvider = (*Plugin)(nil)
)

// NewPlugin creates a new anonymous authentication plugin
func NewPlugin(opts ...Option) *Plugin {
	return &Plugin{opts: opts}
}

// Name returns the plugin identifier
func (p *Plugin) Name() string {
	return PluginName
}

// Init initializes the anonymous plugin
func (p *Plugin) Init(ctx plugin.Context) error {
	p.ctx = ctx

	// Type-assert to get AuthProvider
	auth, ok := ctx.Auth.(AuthProvider)
	if !ok {
		ctx.Logger.Warn("anonymous plugin disabled: auth doesn't support required interface")
		return nil
	}
	p.auth = auth

	// Require database for cleanup functionality
	if ctx.DB == nil {
		ctx.Logger.Warn("anonymous plugin disabled: no database connection")
		return nil
	}

	// Ensure the is_anonymous column exists on the users table
	if err := p.ensureUserExtensionColumns(ctx.DB); err != nil {
		ctx.Logger.Error("anonymous plugin: failed to ensure schema", "error", err)
		return err
	}

	// Build configuration
	config := DefaultConfig()
	for _, opt := range p.opts {
		opt(&config)
	}

	// Create service
	p.service = NewService(ctx.DB, auth, config, ctx.Logger)

	// Subscribe to SignedIn events for account linking
	if ctx.EventBus != nil {
		_, err := ctx.EventBus.Subscribe(models.EventSignedIn, p.handleSignedInEvent)
		if err != nil {
			return fmt.Errorf("failed to subscribe to signed in event: %w", err)
		}
	}

	ctx.Logger.Info("anonymous plugin initialized",
		"email_domain", config.EmailDomain,
		"ttl_enabled", config.AnonymousUserTTL > 0,
	)

	return nil
}

// ensureUserExtensionColumns adds the is_anonymous column to the users table.
// This extends the core users table with anonymous-specific fields.
// Checks if column exists first to avoid SQL syntax errors.
func (p *Plugin) ensureUserExtensionColumns(db *bun.DB) error {
	ctx := context.Background()

	// Check if column already exists to avoid SQL syntax issues
	var count int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM pragma_table_info('users') WHERE name = 'is_anonymous'").Scan(&count); err != nil {
		return fmt.Errorf("failed to check is_anonymous column: %w", err)
	}

	if count > 0 {
		// Column already exists
		return nil
	}

	// Add the column
	if _, err := db.ExecContext(ctx, "ALTER TABLE users ADD COLUMN is_anonymous BOOLEAN DEFAULT FALSE"); err != nil {
		return fmt.Errorf("failed to add is_anonymous column: %w", err)
	}

	return nil
}

// Close cleans up plugin resources
func (p *Plugin) Close() error {
	if p.service != nil {
		return p.service.Close()
	}
	return nil
}

// Routes returns the anonymous authentication endpoints
func (p *Plugin) Routes() []plugin.Route {
	if p.service == nil {
		return nil
	}

	return []plugin.Route{
		{
			Method:  "POST",
			Path:    "/anonymous",
			Handler: p.handleAnonymousSignIn(),
		},
	}
}

// Middleware returns middleware to capture previous session
func (p *Plugin) Middleware() []plugin.Middleware {
	if p.service == nil {
		return nil
	}

	return []plugin.Middleware{
		{
			Priority: MiddlewarePriority,
			Handler:  p.capturePreviousSessionMiddleware(),
		},
	}
}

// handleSignedInEvent handles the EventSignedIn event for account linking
func (p *Plugin) handleSignedInEvent(ctx context.Context, e models.Event) error {
	// Get the previous user from context (set by our middleware)
	// This is our local User type which includes the IsAnonymous field
	previousUser := GetPreviousUser(ctx)
	if previousUser == nil || !previousUser.IsAnonymous {
		// No previous user or not anonymous - nothing to do
		return nil
	}

	// Get the new user from the event payload
	var payload models.SignedInPayload
	if err := e.UnmarshalPayload(&payload); err != nil {
		p.ctx.Logger.Error("failed to unmarshal signed in payload", "error", err)
		return nil
	}

	// Don't link if it's the same user (shouldn't happen, but be safe)
	if previousUser.ID == payload.User.ID {
		return nil
	}

	// Convert models.User to plugin.User for the callback
	// Note: The new user is not anonymous (they just signed in with real credentials)
	newUser := &plugin.User{
		ID:            payload.User.ID,
		Email:         payload.User.Email,
		EmailVerified: payload.User.EmailVerified,
		Name:          payload.User.Name,
		Image:         payload.User.Image,
		Role:          payload.User.Role,
		Banned:        payload.User.Banned,
		CreatedAt:     payload.User.CreatedAt,
		UpdatedAt:     payload.User.UpdatedAt,
	}

	// Handle the account linking - pass the anonymous user (our local type)
	// and the new user (converted to our local type for the callback)
	anonUserForCallback := previousUser.ToPluginUser()
	return p.service.HandleAccountLink(ctx, anonUserForCallback, newUser)
}
