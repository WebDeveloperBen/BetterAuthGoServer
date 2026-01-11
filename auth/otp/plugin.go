// Package otp provides one-time password/token functionality for verification flows.
// This includes password reset tokens, email verification tokens, and email change tokens.
//
// Unlike JWT tokens (which are stateless and self-contained), OTP tokens are:
//   - Stored in the database (hashed)
//   - One-time use (consumed when validated)
//   - Sent via email for user verification
//
// Usage:
//
//	auth.Use(otp.NewPlugin(
//	    otp.WithPasswordResetExpiry(2 * time.Hour),
//	))
package otp

import (
	"context"
	"errors"

	otpdb "github.com/webdeveloperben/BetterAuthGoServer/auth/otp/db"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

const (
	// PluginName is the unique identifier for this plugin
	PluginName = "otp"
)

// Plugin implements the OTP functionality as a plugin.
type Plugin struct {
	ctx     plugin.Context
	store   TokenStore
	dbStore *otpdb.Store
	service *Service
	opts    []Option
}

// Compile-time interface checks
var (
	_ plugin.Plugin                     = (*Plugin)(nil)
	_ plugin.EmailVerificationProvider  = (*Plugin)(nil)
	_ plugin.PasswordResetTokenProvider = (*Plugin)(nil)
)

// NewPlugin creates a new OTP plugin with the given options.
func NewPlugin(opts ...Option) *Plugin {
	return &Plugin{opts: opts}
}

// Name returns the plugin name.
func (p *Plugin) Name() string {
	return PluginName
}

// Init initializes the plugin with the auth context.
func (p *Plugin) Init(ctx plugin.Context) error {
	p.ctx = ctx

	// Require database access via RawDB
	if ctx.RawDB == nil {
		ctx.Logger.Warn("otp plugin: no database available, plugin disabled")
		return nil
	}

	// Build config from options
	config := DefaultConfig()
	for _, opt := range p.opts {
		opt(&config)
	}

	// Create the plugin's own store using raw DB access
	p.dbStore = otpdb.New(ctx.RawDB, ctx.Dialect)
	p.store = NewStoreAdapter(p.dbStore)
	p.service = NewService(p.store, ctx.Hasher, config)

	ctx.Logger.Info("otp plugin initialized")
	return nil
}

// Close cleans up plugin resources.
func (p *Plugin) Close() error {
	return nil
}

// Service returns the OTP service for use by Auth.
// Returns nil if the plugin wasn't properly initialized.
func (p *Plugin) Service() *Service {
	return p.service
}

// IsEnabled returns true if the plugin is properly initialized.
func (p *Plugin) IsEnabled() bool {
	return p.service != nil
}

// CreateEmailVerificationToken implements plugin.EmailVerificationProvider.
func (p *Plugin) CreateEmailVerificationToken(ctx context.Context, userID string) (string, error) {
	if p.service == nil {
		return "", ErrPluginNotConfigured
	}
	return p.service.CreateToken(ctx, userID, TokenTypeEmailVerification)
}

// ConsumeEmailVerificationToken implements plugin.EmailVerificationProvider.
func (p *Plugin) ConsumeEmailVerificationToken(ctx context.Context, rawToken string) (string, error) {
	if p.service == nil {
		return "", ErrPluginNotConfigured
	}
	tok, err := p.service.ConsumeToken(ctx, rawToken, TokenTypeEmailVerification)
	if err != nil {
		return "", p.mapError(err)
	}
	return tok.UserID, nil
}

// CreatePasswordResetToken implements plugin.PasswordResetTokenProvider.
func (p *Plugin) CreatePasswordResetToken(ctx context.Context, userID string) (string, error) {
	if p.service == nil {
		return "", ErrPluginNotConfigured
	}
	return p.service.CreateToken(ctx, userID, TokenTypePasswordReset)
}

// ConsumePasswordResetToken implements plugin.PasswordResetTokenProvider.
func (p *Plugin) ConsumePasswordResetToken(ctx context.Context, rawToken string) (string, error) {
	if p.service == nil {
		return "", ErrPluginNotConfigured
	}
	tok, err := p.service.ConsumeToken(ctx, rawToken, TokenTypePasswordReset)
	if err != nil {
		return "", p.mapError(err)
	}
	return tok.UserID, nil
}

// mapError maps OTP errors to standard verification errors.
func (p *Plugin) mapError(err error) error {
	if errors.Is(err, ErrTokenNotFound) {
		return models.ErrVerificationNotFound
	}
	if errors.Is(err, ErrTokenExpired) {
		return models.ErrVerificationExpired
	}
	return err
}
