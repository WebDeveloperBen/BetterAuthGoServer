package jwt

import (
	"context"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// Option is a functional option for configuring the JWT plugin
type Option func(*Config)

// WithAlgorithm sets the JWT signing algorithm
func WithAlgorithm(alg Algorithm) Option {
	return func(c *Config) {
		c.Algorithm = alg
	}
}

// WithAccessTTL sets the access token TTL
func WithAccessTTL(ttl time.Duration) Option {
	return func(c *Config) {
		c.AccessTokenTTL = ttl
	}
}

// WithRefreshTTL sets the refresh token TTL
func WithRefreshTTL(ttl time.Duration) Option {
	return func(c *Config) {
		c.RefreshTokenTTL = ttl
	}
}

// WithIssuer sets the JWT issuer claim
func WithIssuer(issuer string) Option {
	return func(c *Config) {
		c.Issuer = issuer
	}
}

// WithAudience sets the JWT audience claim
func WithAudience(audience string) Option {
	return func(c *Config) {
		c.Audience = audience
	}
}

// WithTokenBlocklist sets a custom token blocklist
func WithTokenBlocklist(blocklist TokenBlocklist) Option {
	return func(c *Config) {
		c.TokenBlocklist = blocklist
	}
}

// WithKeySource sets the key source for asymmetric algorithms.
// Use KeySourceDatabase for database-backed keys with encryption and rotation.
// Use KeySourceConfig (default) for config-provided PEM keys.
func WithKeySource(source KeySource) Option {
	return func(c *Config) {
		c.KeySource = source
	}
}

// WithPrivateKey sets the private key for config-based asymmetric algorithms.
// The key should be PEM-encoded.
func WithPrivateKey(key []byte) Option {
	return func(c *Config) {
		c.PrivateKey = key
	}
}

// WithPublicKey sets the public key for config-based asymmetric algorithms.
// The key should be PEM-encoded.
func WithPublicKey(key []byte) Option {
	return func(c *Config) {
		c.PublicKey = key
	}
}

const (
	PluginName         = "jwt"
	MiddlewarePriority = 15 // After auth middleware, before business logic
)

// Plugin wraps JWT functionality as an auth plugin
type Plugin struct {
	service    *Service
	keyManager *KeyManager
	ctx        plugin.Context
	auth       AuthProvider
	opts       []Option
}

// WithKeyRotationGracePeriod sets how long rotated keys remain valid for verification.
// Default is 24 hours. Only used when KeySource is KeySourceDatabase.
func WithKeyRotationGracePeriod(d time.Duration) Option {
	return func(c *Config) {
		c.KeyRotationGracePeriod = d
	}
}

// WithKeySize sets the RSA key size for database-backed keys.
// Default is 2048. Only applies to RSA algorithms.
func WithKeySize(size int) Option {
	return func(c *Config) {
		c.KeySize = size
	}
}

// Ensure Plugin implements required interfaces
var (
	_ plugin.Plugin             = (*Plugin)(nil)
	_ plugin.RoutesProvider     = (*Plugin)(nil)
	_ plugin.MiddlewareProvider = (*Plugin)(nil)
	_ plugin.JWTTokenGenerator  = (*Plugin)(nil)
	_ plugin.MigrationsProvider = (*Plugin)(nil)
)

// NewPlugin creates a new JWT plugin with the given options
func NewPlugin(opts ...Option) *Plugin {
	return &Plugin{
		opts: opts,
	}
}

// Name returns the plugin identifier
func (p *Plugin) Name() string {
	return PluginName
}

// Init initializes the JWT plugin
func (p *Plugin) Init(ctx plugin.Context) error {
	p.ctx = ctx

	// Type-assert to get AuthProvider
	auth, ok := ctx.Auth.(AuthProvider)
	if !ok {
		return nil // Auth doesn't support JWT operations
	}
	p.auth = auth

	// Create JWT service config
	config := DefaultConfig()

	// Apply user options
	for _, opt := range p.opts {
		opt(&config)
	}

	// Set defaults from context
	if config.Issuer == "" {
		config.Issuer = ctx.BaseURL
	}
	if config.Secret == "" {
		config.Secret = ctx.Secret
	}

	// Set up KeyManager for database-backed asymmetric keys
	if config.KeySource == KeySourceDatabase {
		if ctx.DB == nil {
			return ErrDatabaseRequired
		}
		if ctx.Encryptor == nil {
			return ErrEncryptorRequired
		}

		// Build KeyManager options
		var kmOpts []KeyManagerOption
		if config.KeyRotationGracePeriod > 0 {
			kmOpts = append(kmOpts, WithKeyManagerGracePeriod(config.KeyRotationGracePeriod))
		}
		if config.KeySize > 0 {
			kmOpts = append(kmOpts, WithKeyManagerKeySize(config.KeySize))
		}
		kmOpts = append(kmOpts, WithKeyManagerLogger(ctx.Logger))

		// Create KeyManager
		km := NewKeyManager(ctx.DB, ctx.Encryptor, config.Algorithm, kmOpts...)
		p.keyManager = km
		config.KeyManager = km

		// Ensure there's an active key (generates one if needed)
		if _, err := km.EnsureActiveKey(context.Background()); err != nil {
			return err
		}

		ctx.Logger.Info("jwt plugin: using database-backed keys",
			"algorithm", config.Algorithm,
		)
	}

	// Use database-backed blocklist if available, otherwise use memory
	if config.TokenBlocklist == nil {
		if ctx.DB != nil {
			config.TokenBlocklist = NewDBTokenBlocklist(ctx.DB)
		} else {
			config.TokenBlocklist = NewMemoryTokenBlocklist()
		}
	}

	// Create the JWT service
	service, err := NewService(config)
	if err != nil {
		return err
	}

	p.service = service
	return nil
}

// Close cleans up plugin resources
func (p *Plugin) Close() error {
	return nil
}

// Migrations returns the database models for auto-migration.
// Only returns models when using database-backed keys.
func (p *Plugin) Migrations() []any {
	return []any{
		&JWK{},
		&RevokedToken{},
	}
}

// Routes returns the JWT token endpoints
func (p *Plugin) Routes() []plugin.Route {
	routes := []plugin.Route{
		{
			Method:  "POST",
			Path:    "/token",
			Handler: p.TokenHandler(),
		},
		{
			Method:  "POST",
			Path:    "/token/refresh",
			Handler: p.TokenRefreshHandler(),
		},
		{
			Method:  "POST",
			Path:    "/token/revoke",
			Handler: p.TokenRevokeHandler(),
		},
		{
			Method:  "POST",
			Path:    "/token/introspect",
			Handler: p.TokenIntrospectHandler(),
		},
	}

	// Add JWKS endpoint if using database-backed keys
	if p.keyManager != nil {
		routes = append(routes, plugin.Route{
			Method:  "GET",
			Path:    "/.well-known/jwks.json",
			Handler: JWKSHandler(p.keyManager),
		})
		routes = append(routes, plugin.Route{
			Method:  "POST",
			Path:    "/keys/rotate",
			Handler: p.KeyRotateHandler(),
		})
	}

	return routes
}

// Middleware returns JWT authentication middleware
func (p *Plugin) Middleware() []plugin.Middleware {
	return []plugin.Middleware{
		{
			Priority: MiddlewarePriority,
			Handler:  p.jwtAuthMiddleware(),
		},
	}
}

// GenerateTokensForSession implements plugin.JWTTokenGenerator.
// This allows other plugins to request JWT tokens for a session.
// If the session is an impersonation session, the "act" claim will be set per RFC 8693.
func (p *Plugin) GenerateTokensForSession(ctx context.Context, session *plugin.Session, user *plugin.User) (*plugin.TokenPair, error) {
	if p.service == nil {
		return nil, ErrNotInitialized
	}

	userInfo := UserInfo{
		ID:            user.ID,
		Email:         user.Email,
		Name:          user.Name,
		EmailVerified: user.EmailVerified,
		ActorID:       session.ImpersonatedBy, // Set actor for impersonation sessions
	}

	pair, err := p.service.GenerateTokenPair(ctx, userInfo, session.ID)
	if err != nil {
		return nil, err
	}

	return &plugin.TokenPair{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		TokenType:    pair.TokenType,
		ExpiresIn:    pair.ExpiresIn,
	}, nil
}
