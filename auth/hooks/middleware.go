package hooks

import (
	"log/slog"
)

// Middleware is a function that processes hook context.
// Return nil to continue, or an error (preferably *APIError) to abort.
type Middleware func(ctx *Context) error

// MiddlewareHooks holds global before/after middleware chains.
// These run on every auth operation, allowing cross-cutting concerns
// like logging, validation, rate limiting, etc.
type MiddlewareHooks struct {
	// Before runs before any auth operation.
	// Returning an error aborts the operation.
	// If an *APIError is returned, it's sent as the response.
	Before []Middleware

	// After runs after any auth operation completes successfully.
	// Errors are logged but don't affect the response.
	After []Middleware
}

// RunBefore executes all before middleware in sequence.
// Stops and returns on the first error.
func (h *MiddlewareHooks) RunBefore(ctx *Context, logger *slog.Logger) error {
	if h == nil {
		return nil
	}

	for i, middleware := range h.Before {
		if err := middleware(ctx); err != nil {
			if logger != nil {
				logger.Debug("before hook aborted",
					"hook_index", i,
					"path", ctx.Path,
					"error", err.Error(),
				)
			}
			return err
		}

		// Check if middleware already sent a response
		if ctx.HasResponded() {
			return nil
		}
	}

	return nil
}

// RunAfter executes all after middleware in sequence.
// Errors are logged but don't stop execution.
func (h *MiddlewareHooks) RunAfter(ctx *Context, logger *slog.Logger) {
	if h == nil {
		return
	}

	for i, middleware := range h.After {
		if err := middleware(ctx); err != nil {
			if logger != nil {
				logger.Warn("after hook error",
					"hook_index", i,
					"path", ctx.Path,
					"error", err.Error(),
				)
			}
		}
	}
}

// CreateMiddleware wraps a function as middleware.
// This is a convenience function for creating middleware.
func CreateMiddleware(fn func(ctx *Context) error) Middleware {
	return fn
}

// ChainMiddleware combines multiple middleware into one.
func ChainMiddleware(middlewares ...Middleware) Middleware {
	return func(ctx *Context) error {
		for _, m := range middlewares {
			if err := m(ctx); err != nil {
				return err
			}
			if ctx.HasResponded() {
				return nil
			}
		}
		return nil
	}
}

// SkipPaths returns middleware that skips execution for certain paths.
func SkipPaths(middleware Middleware, paths ...string) Middleware {
	skipSet := make(map[string]bool)
	for _, p := range paths {
		skipSet[p] = true
	}

	return func(ctx *Context) error {
		if skipSet[ctx.Path] {
			return nil
		}
		return middleware(ctx)
	}
}

// OnlyPaths returns middleware that only runs for certain paths.
func OnlyPaths(middleware Middleware, paths ...string) Middleware {
	pathSet := make(map[string]bool)
	for _, p := range paths {
		pathSet[p] = true
	}

	return func(ctx *Context) error {
		if !pathSet[ctx.Path] {
			return nil
		}
		return middleware(ctx)
	}
}

// LoggingMiddleware creates middleware that logs all auth operations.
func LoggingMiddleware(logger *slog.Logger) Middleware {
	return func(ctx *Context) error {
		logger.Info("auth operation",
			"path", ctx.Path,
			"method", ctx.Method,
			"client_ip", ctx.ClientIP(),
		)
		return nil
	}
}

// RequireEmailDomain creates middleware that requires emails to match a domain.
// Only applies to sign-up operations.
func RequireEmailDomain(domain string) Middleware {
	return func(ctx *Context) error {
		if ctx.Path != "/sign-up" {
			return nil
		}

		email := ctx.GetBodyString("email")
		if email == "" {
			return nil // Let the handler deal with missing email
		}

		// Check domain
		atIdx := -1
		for i := len(email) - 1; i >= 0; i-- {
			if email[i] == '@' {
				atIdx = i
				break
			}
		}

		if atIdx == -1 || email[atIdx+1:] != domain {
			return NewAPIErrorWithCode("BAD_REQUEST", "email domain not allowed", "INVALID_EMAIL_DOMAIN")
		}

		return nil
	}
}

// NewMiddlewareHooks creates a new MiddlewareHooks with the given before/after chains.
func NewMiddlewareHooks(before []Middleware, after []Middleware) *MiddlewareHooks {
	return &MiddlewareHooks{
		Before: before,
		After:  after,
	}
}

// AddBefore adds middleware to the before chain
func (h *MiddlewareHooks) AddBefore(middlewares ...Middleware) {
	h.Before = append(h.Before, middlewares...)
}

// AddAfter adds middleware to the after chain
func (h *MiddlewareHooks) AddAfter(middlewares ...Middleware) {
	h.After = append(h.After, middlewares...)
}

// PrependBefore adds middleware to the beginning of the before chain
func (h *MiddlewareHooks) PrependBefore(middlewares ...Middleware) {
	h.Before = append(middlewares, h.Before...)
}

// PrependAfter adds middleware to the beginning of the after chain
func (h *MiddlewareHooks) PrependAfter(middlewares ...Middleware) {
	h.After = append(middlewares, h.After...)
}
