package ratelimit

import (
	"log/slog"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

const (
	// PluginName is the unique identifier for the rate limit plugin.
	PluginName = "ratelimit"

	// MiddlewarePriority determines when rate limiting runs in the middleware chain.
	// Lower values run first. Rate limiting should run early to reject requests quickly.
	MiddlewarePriority = 10
)

// Plugin wraps a rate limiter as an auth plugin.
// It implements plugin.Plugin and plugin.MiddlewareProvider.
type Plugin struct {
	ctx     plugin.Context
	limiter *Limiter
	opts    []Option
	logger  *slog.Logger
}

// Ensure Plugin implements the required interfaces.
var (
	_ plugin.Plugin             = (*Plugin)(nil)
	_ plugin.MiddlewareProvider = (*Plugin)(nil)
)

// NewPlugin creates a new rate limit plugin with the given options.
//
// For single-instance deployments, the default in-memory backend works well.
// For clustered deployments, use a shared backend like Redis:
//
//	import kvredis "github.com/webdeveloperben/BetterAuthGoServer/auth/kv/redis"
//
//	redisStore := kvredis.NewStore(&redis.Options{Addr: "localhost:6379"})
//	auth.Use(ratelimit.NewPlugin(
//	    ratelimit.WithLimit(100, time.Minute),
//	    ratelimit.WithBackend(kvredis.NewRateLimiter(redisStore)),
//	))
func NewPlugin(opts ...Option) *Plugin {
	return &Plugin{
		opts: opts,
	}
}

// Name returns the plugin identifier.
func (p *Plugin) Name() string {
	return PluginName
}

// Init initializes the rate limiter.
func (p *Plugin) Init(ctx plugin.Context) error {
	p.ctx = ctx

	// Use provided logger or default
	if ctx.Logger != nil {
		p.logger = ctx.Logger
	} else {
		p.logger = slog.Default()
	}

	// Build config from options
	config := DefaultConfig()
	for _, opt := range p.opts {
		opt(&config)
	}

	// Create limiter with config
	p.limiter = NewLimiter(config, p.logger)

	p.logger.Info("ratelimit plugin initialized",
		"max_requests", config.MaxRequests,
		"window", config.Window,
		"backend", backendType(config.Backend),
	)

	return nil
}

// backendType returns a string describing the backend type for logging.
func backendType(backend any) string {
	if backend == nil {
		return "memory"
	}
	return "custom"
}

// Close stops the rate limiter and releases resources.
func (p *Plugin) Close() error {
	if p.limiter != nil {
		return p.limiter.Close()
	}
	return nil
}

// Middleware returns the rate limiting middleware.
func (p *Plugin) Middleware() []plugin.Middleware {
	if p.limiter == nil {
		return nil
	}

	return []plugin.Middleware{
		{
			Priority: MiddlewarePriority,
			Handler:  p.limiter.Middleware(),
		},
	}
}

// Limiter returns the underlying rate limiter.
// This can be used to access rate limit state directly.
func (p *Plugin) Limiter() *Limiter {
	return p.limiter
}
