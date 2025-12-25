package otel

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Metrics holds all auth-related metric instruments
type Metrics struct {
	// SignUps counts total sign-up attempts
	SignUps metric.Int64Counter

	// SignIns counts total sign-in attempts with success/failure labels
	SignIns metric.Int64Counter

	// SignInDuration measures sign-in operation duration
	SignInDuration metric.Float64Histogram

	// SignOuts counts total sign-out operations
	SignOuts metric.Int64Counter

	// ActiveSessions is a gauge of currently active sessions
	ActiveSessions metric.Int64UpDownCounter

	// PasswordResets counts password reset requests
	PasswordResets metric.Int64Counter

	// PasswordChanges counts password change operations
	PasswordChanges metric.Int64Counter

	// EmailVerifications counts email verification operations
	EmailVerifications metric.Int64Counter

	// OAuthAttempts counts OAuth authentication attempts by provider
	OAuthAttempts metric.Int64Counter

	// TokenOperations counts JWT token operations (issue, refresh, revoke)
	TokenOperations metric.Int64Counter

	// RateLimitExceeded counts rate limit exceeded events
	RateLimitExceeded metric.Int64Counter

	// AdminOperations counts admin operations (ban, unban, role change)
	AdminOperations metric.Int64Counter

	// AuthErrors counts authentication errors by type
	AuthErrors metric.Int64Counter
}

// NewMetrics creates and registers all auth metrics
func NewMetrics(meter metric.Meter) (*Metrics, error) {
	m := &Metrics{}
	var err error

	m.SignUps, err = meter.Int64Counter(
		"auth.signups.total",
		metric.WithDescription("Total number of sign-up attempts"),
		metric.WithUnit("{attempt}"),
	)
	if err != nil {
		return nil, err
	}

	m.SignIns, err = meter.Int64Counter(
		"auth.signins.total",
		metric.WithDescription("Total number of sign-in attempts"),
		metric.WithUnit("{attempt}"),
	)
	if err != nil {
		return nil, err
	}

	m.SignInDuration, err = meter.Float64Histogram(
		"auth.signins.duration",
		metric.WithDescription("Duration of sign-in operations"),
		metric.WithUnit("ms"),
		metric.WithExplicitBucketBoundaries(1, 5, 10, 25, 50, 100, 250, 500, 1000),
	)
	if err != nil {
		return nil, err
	}

	m.SignOuts, err = meter.Int64Counter(
		"auth.signouts.total",
		metric.WithDescription("Total number of sign-out operations"),
		metric.WithUnit("{operation}"),
	)
	if err != nil {
		return nil, err
	}

	m.ActiveSessions, err = meter.Int64UpDownCounter(
		"auth.sessions.active",
		metric.WithDescription("Number of currently active sessions"),
		metric.WithUnit("{session}"),
	)
	if err != nil {
		return nil, err
	}

	m.PasswordResets, err = meter.Int64Counter(
		"auth.password_resets.total",
		metric.WithDescription("Total number of password reset requests"),
		metric.WithUnit("{request}"),
	)
	if err != nil {
		return nil, err
	}

	m.PasswordChanges, err = meter.Int64Counter(
		"auth.password_changes.total",
		metric.WithDescription("Total number of password change operations"),
		metric.WithUnit("{operation}"),
	)
	if err != nil {
		return nil, err
	}

	m.EmailVerifications, err = meter.Int64Counter(
		"auth.email_verifications.total",
		metric.WithDescription("Total number of email verification operations"),
		metric.WithUnit("{operation}"),
	)
	if err != nil {
		return nil, err
	}

	m.OAuthAttempts, err = meter.Int64Counter(
		"auth.oauth.total",
		metric.WithDescription("Total number of OAuth authentication attempts"),
		metric.WithUnit("{attempt}"),
	)
	if err != nil {
		return nil, err
	}

	m.TokenOperations, err = meter.Int64Counter(
		"auth.token.operations.total",
		metric.WithDescription("Total number of JWT token operations"),
		metric.WithUnit("{operation}"),
	)
	if err != nil {
		return nil, err
	}

	m.RateLimitExceeded, err = meter.Int64Counter(
		"auth.rate_limit.exceeded.total",
		metric.WithDescription("Total number of rate limit exceeded events"),
		metric.WithUnit("{event}"),
	)
	if err != nil {
		return nil, err
	}

	m.AdminOperations, err = meter.Int64Counter(
		"auth.admin.operations.total",
		metric.WithDescription("Total number of admin operations"),
		metric.WithUnit("{operation}"),
	)
	if err != nil {
		return nil, err
	}

	m.AuthErrors, err = meter.Int64Counter(
		"auth.errors.total",
		metric.WithDescription("Total number of authentication errors"),
		metric.WithUnit("{error}"),
	)
	if err != nil {
		return nil, err
	}

	return m, nil
}

// Common attribute keys
var (
	AttrSuccess   = attribute.Key("success")
	AttrProvider  = attribute.Key("provider")
	AttrOperation = attribute.Key("operation")
	AttrErrorType = attribute.Key("error_type")
	AttrEndpoint  = attribute.Key("endpoint")
)

// RecordSignUp records a sign-up attempt
func (m *Metrics) RecordSignUp(ctx context.Context, success bool) {
	m.SignUps.Add(ctx, 1, metric.WithAttributes(AttrSuccess.Bool(success)))
}

// RecordSignIn records a sign-in attempt with duration
func (m *Metrics) RecordSignIn(ctx context.Context, success bool, durationMs float64) {
	attrs := metric.WithAttributes(AttrSuccess.Bool(success))
	m.SignIns.Add(ctx, 1, attrs)
	m.SignInDuration.Record(ctx, durationMs, attrs)
}

// RecordSignOut records a sign-out operation
func (m *Metrics) RecordSignOut(ctx context.Context) {
	m.SignOuts.Add(ctx, 1)
}

// RecordSessionCreated records a new session creation
func (m *Metrics) RecordSessionCreated(ctx context.Context) {
	m.ActiveSessions.Add(ctx, 1)
}

// RecordSessionDestroyed records a session destruction
func (m *Metrics) RecordSessionDestroyed(ctx context.Context) {
	m.ActiveSessions.Add(ctx, -1)
}

// RecordPasswordReset records a password reset request
func (m *Metrics) RecordPasswordReset(ctx context.Context, success bool) {
	m.PasswordResets.Add(ctx, 1, metric.WithAttributes(AttrSuccess.Bool(success)))
}

// RecordPasswordChange records a password change operation
func (m *Metrics) RecordPasswordChange(ctx context.Context, success bool) {
	m.PasswordChanges.Add(ctx, 1, metric.WithAttributes(AttrSuccess.Bool(success)))
}

// RecordEmailVerification records an email verification operation
func (m *Metrics) RecordEmailVerification(ctx context.Context, success bool) {
	m.EmailVerifications.Add(ctx, 1, metric.WithAttributes(AttrSuccess.Bool(success)))
}

// RecordOAuthAttempt records an OAuth authentication attempt
func (m *Metrics) RecordOAuthAttempt(ctx context.Context, provider string, success bool) {
	m.OAuthAttempts.Add(ctx, 1, metric.WithAttributes(
		AttrProvider.String(provider),
		AttrSuccess.Bool(success),
	))
}

// RecordTokenOperation records a JWT token operation
func (m *Metrics) RecordTokenOperation(ctx context.Context, operation string, success bool) {
	m.TokenOperations.Add(ctx, 1, metric.WithAttributes(
		AttrOperation.String(operation),
		AttrSuccess.Bool(success),
	))
}

// RecordRateLimitExceeded records a rate limit exceeded event
func (m *Metrics) RecordRateLimitExceeded(ctx context.Context, endpoint string) {
	m.RateLimitExceeded.Add(ctx, 1, metric.WithAttributes(AttrEndpoint.String(endpoint)))
}

// RecordAdminOperation records an admin operation
func (m *Metrics) RecordAdminOperation(ctx context.Context, operation string, success bool) {
	m.AdminOperations.Add(ctx, 1, metric.WithAttributes(
		AttrOperation.String(operation),
		AttrSuccess.Bool(success),
	))
}

// RecordAuthError records an authentication error
func (m *Metrics) RecordAuthError(ctx context.Context, errorType string) {
	m.AuthErrors.Add(ctx, 1, metric.WithAttributes(AttrErrorType.String(errorType)))
}
