package auth

import (
	"context"
	"log/slog"
)

// Hooks contains callback functions for auth events
type Hooks struct {
	// OnUserCreated is called after a new user is created
	OnUserCreated func(ctx context.Context, user *User) error

	// OnUserUpdated is called after a user is updated
	OnUserUpdated func(ctx context.Context, user *User) error

	// OnSignIn is called after a successful sign in
	OnSignIn func(ctx context.Context, user *User, session *Session) error

	// OnSignOut is called after a sign out
	OnSignOut func(ctx context.Context, user *User, session *Session) error

	// OnPasswordChanged is called after a password is changed
	OnPasswordChanged func(ctx context.Context, user *User) error

	// OnPasswordResetRequested is called when a password reset is requested
	// The token is the raw token that should be sent to the user
	OnPasswordResetRequested func(ctx context.Context, user *User, token string) error

	// OnEmailVerified is called after an email is verified
	OnEmailVerified func(ctx context.Context, user *User) error

	// OnEmailVerificationRequested is called when email verification is requested
	// The token is the raw token that should be sent to the user
	OnEmailVerificationRequested func(ctx context.Context, user *User, token string) error

	// OnOAuthAccountLinked is called when an OAuth account is linked to a user
	OnOAuthAccountLinked func(ctx context.Context, user *User, account *Account) error
}

// fire executes a hook if it's set, logging any errors
func (h *Hooks) fire(_ context.Context, logger *slog.Logger, name string, fn func() error) {
	if fn == nil {
		return
	}
	if err := fn(); err != nil {
		logger.Warn("hook failed", "hook", name, "error", err)
	}
}

// fireUserCreated fires the OnUserCreated hook
func (h *Hooks) fireUserCreated(ctx context.Context, logger *slog.Logger, user *User) {
	if h.OnUserCreated != nil {
		h.fire(ctx, logger, "OnUserCreated", func() error {
			return h.OnUserCreated(ctx, user)
		})
	}
}

// FireUserUpdated fires the OnUserUpdated hook
func (h *Hooks) FireUserUpdated(ctx context.Context, logger *slog.Logger, user *User) {
	if h.OnUserUpdated != nil {
		h.fire(ctx, logger, "OnUserUpdated", func() error {
			return h.OnUserUpdated(ctx, user)
		})
	}
}

// fireSignIn fires the OnSignIn hook
func (h *Hooks) fireSignIn(ctx context.Context, logger *slog.Logger, user *User, session *Session) {
	if h.OnSignIn != nil {
		h.fire(ctx, logger, "OnSignIn", func() error {
			return h.OnSignIn(ctx, user, session)
		})
	}
}

// fireSignOut fires the OnSignOut hook
func (h *Hooks) fireSignOut(ctx context.Context, logger *slog.Logger, user *User, session *Session) {
	if h.OnSignOut != nil {
		h.fire(ctx, logger, "OnSignOut", func() error {
			return h.OnSignOut(ctx, user, session)
		})
	}
}

// firePasswordChanged fires the OnPasswordChanged hook
func (h *Hooks) firePasswordChanged(ctx context.Context, logger *slog.Logger, user *User) {
	if h.OnPasswordChanged != nil {
		h.fire(ctx, logger, "OnPasswordChanged", func() error {
			return h.OnPasswordChanged(ctx, user)
		})
	}
}

// firePasswordResetRequested fires the OnPasswordResetRequested hook
func (h *Hooks) firePasswordResetRequested(ctx context.Context, logger *slog.Logger, user *User, rawToken string) {
	if h.OnPasswordResetRequested != nil {
		h.fire(ctx, logger, "OnPasswordResetRequested", func() error {
			return h.OnPasswordResetRequested(ctx, user, rawToken)
		})
	}
}

// fireEmailVerified fires the OnEmailVerified hook
func (h *Hooks) fireEmailVerified(ctx context.Context, logger *slog.Logger, user *User) {
	if h.OnEmailVerified != nil {
		h.fire(ctx, logger, "OnEmailVerified", func() error {
			return h.OnEmailVerified(ctx, user)
		})
	}
}

// fireEmailVerificationRequested fires the OnEmailVerificationRequested hook
func (h *Hooks) fireEmailVerificationRequested(ctx context.Context, logger *slog.Logger, user *User, rawToken string) {
	if h.OnEmailVerificationRequested != nil {
		h.fire(ctx, logger, "OnEmailVerificationRequested", func() error {
			return h.OnEmailVerificationRequested(ctx, user, rawToken)
		})
	}
}

// fireOAuthAccountLinked fires the OnOAuthAccountLinked hook
func (h *Hooks) fireOAuthAccountLinked(ctx context.Context, logger *slog.Logger, user *User, account *Account) {
	if h.OnOAuthAccountLinked != nil {
		h.fire(ctx, logger, "OnOAuthAccountLinked", func() error {
			return h.OnOAuthAccountLinked(ctx, user, account)
		})
	}
}
