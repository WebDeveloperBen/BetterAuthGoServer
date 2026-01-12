package jwt

import (
	"context"
	"fmt"
	"net/http"
	"time"

	jwtdb "github.com/webdeveloperben/BetterAuthGoServer/auth/jwt/db"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/kv"
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

// WithRequireEmailVerification enforces verified emails before token issuance.
func WithRequireEmailVerification(required bool) Option {
	return func(c *Config) {
		c.RequireEmailVerification = required
	}
}

// WithLockoutThreshold sets failed attempts before lockout for JWT password grant.
func WithLockoutThreshold(n int) Option {
	return func(c *Config) {
		c.LockoutThreshold = n
	}
}

// WithLockoutDuration sets the lockout duration for JWT password grant.
func WithLockoutDuration(d time.Duration) Option {
	return func(c *Config) {
		c.LockoutDuration = d
	}
}

// WithLockoutStore sets a custom kv.Store for tracking failed attempts.
func WithLockoutStore(store kv.Store) Option {
	return func(c *Config) {
		c.LockoutStore = store
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
	service           *Service
	keyManagerAdapter *KeyManagerAdapter // sqlc-based key manager
	dbStore           *jwtdb.Store       // plugin's own store
	ctx               plugin.Context
	auth              AuthProvider
	opts              []Option
	lockout           *lockoutService
	rotateKeyLimiter  kv.RateLimiter
	ownsRotateLimiter bool
	keyRotationRoles  []string
	rotateKeyRateLimitMax    int
	rotateKeyRateLimitWindow time.Duration
	requireEmailVerification bool
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

// WithRotateKeyRateLimit sets the rate limit for /keys/rotate.
// Set max to 0 to disable.
func WithRotateKeyRateLimit(max int, window time.Duration) Option {
	return func(c *Config) {
		c.RotateKeyRateLimitMax = max
		c.RotateKeyRateLimitWindow = window
	}
}

// WithRotateKeyRateLimiter sets a custom rate limiter for /keys/rotate.
// If nil, an in-memory limiter is used.
func WithRotateKeyRateLimiter(limiter kv.RateLimiter) Option {
	return func(c *Config) {
		c.RotateKeyRateLimiter = limiter
	}
}

// WithKeyRotationRoles sets which roles can rotate keys.
// Defaults to ["admin"].
func WithKeyRotationRoles(roles ...string) Option {
	return func(c *Config) {
		c.KeyRotationRoles = roles
	}
}

// Ensure Plugin implements required interfaces
var (
	_ plugin.Plugin             = (*Plugin)(nil)
	_ plugin.RoutesProvider     = (*Plugin)(nil)
	_ plugin.MiddlewareProvider = (*Plugin)(nil)
	_ plugin.JWTTokenGenerator  = (*Plugin)(nil)
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

	if !config.RequireEmailVerification {
		config.RequireEmailVerification = ctx.RequireEmailVerification
	}

	// Set defaults from context
	if config.Issuer == "" {
		config.Issuer = ctx.BaseURL
	}
	if config.Secret == "" {
		config.Secret = ctx.Secret
	}

	// Create plugin's own store if database is available
	if ctx.RawDB != nil {
		store, err := jwtdb.New(ctx.RawDB, ctx.Dialect)
		if err != nil {
			return fmt.Errorf("jwt plugin: failed to create store: %w", err)
		}
		p.dbStore = store
	}

	// Set up KeyManager for database-backed asymmetric keys
	if config.KeySource == KeySourceDatabase {
		if p.dbStore == nil {
			return ErrDatabaseRequired
		}
		if ctx.Encryptor == nil {
			return ErrEncryptorRequired
		}

		// Build KeyManagerAdapter options
		var kmOpts []KeyManagerAdapterOption
		if config.KeyRotationGracePeriod > 0 {
			kmOpts = append(kmOpts, WithAdapterGracePeriod(config.KeyRotationGracePeriod))
		}
		if config.KeySize > 0 {
			kmOpts = append(kmOpts, WithAdapterKeySize(config.KeySize))
		}
		kmOpts = append(kmOpts, WithAdapterLogger(ctx.Logger))

		// Create KeyManagerAdapter using the plugin's own store
		km := NewKeyManagerAdapter(p.dbStore, ctx.Encryptor, config.Algorithm, kmOpts...)
		p.keyManagerAdapter = km
		config.KeyManager = km

		// Ensure there's an active key (generates one if needed)
		ctxTimeout, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := km.EnsureActiveKey(ctxTimeout); err != nil {
			return err
		}

		ctx.Logger.Info("jwt plugin: using database-backed keys",
			"algorithm", config.Algorithm,
		)
	}

	// Use database-backed blocklist if available, otherwise use memory
	if config.TokenBlocklist == nil {
		if p.dbStore != nil {
			config.TokenBlocklist = NewBlocklistAdapter(p.dbStore)
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
	p.lockout = newLockoutService(config.LockoutStore, config.LockoutThreshold, config.LockoutDuration)
	p.requireEmailVerification = config.RequireEmailVerification
	p.keyRotationRoles = config.KeyRotationRoles
	p.rotateKeyRateLimitMax = config.RotateKeyRateLimitMax
	p.rotateKeyRateLimitWindow = config.RotateKeyRateLimitWindow
	if config.RotateKeyRateLimitMax > 0 {
		if config.RotateKeyRateLimiter != nil {
			p.rotateKeyLimiter = config.RotateKeyRateLimiter
		} else {
			p.rotateKeyLimiter = kv.NewMemoryRateLimiter()
			p.ownsRotateLimiter = true
		}
	}
	return nil
}

// Close cleans up plugin resources
func (p *Plugin) Close() error {
	if p.lockout != nil {
		_ = p.lockout.Close()
	}
	if p.rotateKeyLimiter != nil && p.ownsRotateLimiter {
		_ = p.rotateKeyLimiter.Close()
	}
	return nil
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
	if p.keyManagerAdapter != nil {
		routes = append(routes, plugin.Route{
			Method:  "GET",
			Path:    "/.well-known/jwks.json",
			Handler: JWKSHandler(p.keyManagerAdapter),
		})
		routes = append(routes, plugin.Route{
			Method:  "POST",
			Path:    "/keys/rotate",
			Handler: p.KeyRotateHandler(),
			Middleware: []func(http.Handler) http.Handler{
				p.keyRotateAuthoriser(),
				p.keyRotateRateLimiter(),
			},
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
