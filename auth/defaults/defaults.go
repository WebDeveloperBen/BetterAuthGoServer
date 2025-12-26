// Package defaults provides the default plugin bundle for the auth library.
// When Auth.New() is called without WithoutDefaults(), these plugins are
// automatically registered to provide core functionality.
package defaults

import (
	"github.com/webdeveloperben/BetterAuthGoServer/auth/config"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/csrf"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/ratelimit"
)

// Plugins returns the default plugin set based on configuration.
// Called by Auth.New() unless SkipDefaults is true.
//
// Default plugins include:
//   - Rate limiting (if RateLimitEnabled)
//   - CSRF protection (if CSRFEnabled)
//
// Use config.WithoutDefaults() to disable these and build your own plugin set.
func Plugins(cfg *config.Config) []plugin.Plugin {
	var plugins []plugin.Plugin

	// Rate limiting plugin
	if cfg.RateLimitEnabled {
		opts := []ratelimit.Option{
			ratelimit.WithLimit(cfg.AuthRateLimitMax, cfg.RateLimitWindow),
		}
		if cfg.RateLimiterBackend != nil {
			opts = append(opts, ratelimit.WithBackend(cfg.RateLimiterBackend))
		}
		if len(cfg.TrustedProxies) > 0 {
			opts = append(opts, ratelimit.WithTrustedProxies(cfg.TrustedProxies))
		}
		plugins = append(plugins, ratelimit.NewPlugin(opts...))
	}

	// CSRF protection plugin
	if cfg.CSRFEnabled {
		var opts []csrf.Option
		if cfg.CSRFCookieName != "" {
			opts = append(opts, csrf.WithCookieName(cfg.CSRFCookieName))
		}
		if cfg.CSRFHeaderName != "" {
			opts = append(opts, csrf.WithHeaderName(cfg.CSRFHeaderName))
		}
		plugins = append(plugins, csrf.NewPlugin(opts...))
	}

	// Future: Add admin.Plugin() when admin is converted to a default plugin

	return plugins
}
