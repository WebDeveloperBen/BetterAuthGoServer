// Package defaults provides the default plugin bundle for the auth library.
// When Auth.New() is called with WithDefaults(), these plugins are
// automatically registered to provide core functionality.
package defaults

import (
	"github.com/webdeveloperben/BetterAuthGoServer/auth/config"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/csrf"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/otp"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/password"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/ratelimit"
)

// Plugins returns the default plugin set based on configuration.
// Called by Auth.New() when UseDefaults is true (via config.WithDefaults()).
//
// Default plugins include:
//   - OTP (always enabled - required for password reset and email verification)
//   - Password authentication (if PasswordAuthEnabled)
//   - Rate limiting (if RateLimitEnabled)
//   - CSRF protection (if CSRFEnabled)
//
// By default, no plugins are registered. Use config.WithDefaults() to enable
// this bundle, or use Use() to register individual plugins.
func Plugins(cfg *config.Config) []plugin.Plugin {
	var plugins []plugin.Plugin

	// OTP plugin - always enabled (required for password reset and email verification)
	plugins = append(plugins, otp.NewPlugin(
		otp.WithPasswordResetExpiry(cfg.PasswordResetExpiry),
		otp.WithEmailVerificationExpiry(cfg.EmailVerificationExpiry),
	))

	// Password authentication plugin
	if cfg.PasswordAuthEnabled {
		plugins = append(plugins, password.NewPlugin(
			password.WithMinLength(cfg.PasswordMinLength),
			password.WithMaxLength(cfg.PasswordMaxLength),
			password.WithComplexity(cfg.RequirePasswordComplexity),
			password.WithResetExpiry(cfg.PasswordResetExpiry),
			password.WithAutoSignIn(cfg.AutoSignIn),
		))
	}

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

	return plugins
}
