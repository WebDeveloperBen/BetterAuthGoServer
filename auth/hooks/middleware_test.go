package hooks

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMiddlewareHooks_RunBefore(t *testing.T) {
	logger := slog.Default()

	t.Run("runs all hooks in order", func(t *testing.T) {
		var order []int
		mh := &MiddlewareHooks{
			Before: []Middleware{
				func(ctx *Context) error {
					order = append(order, 1)
					return nil
				},
				func(ctx *Context) error {
					order = append(order, 2)
					return nil
				},
				func(ctx *Context) error {
					order = append(order, 3)
					return nil
				},
			},
		}

		ctx := &Context{Path: "/test"}
		err := mh.RunBefore(ctx, logger)

		if err != nil {
			t.Errorf("RunBefore returned error: %v", err)
		}
		if len(order) != 3 || order[0] != 1 || order[1] != 2 || order[2] != 3 {
			t.Errorf("Hooks ran in wrong order: %v", order)
		}
	})

	t.Run("stops on first error", func(t *testing.T) {
		var order []int
		testErr := errors.New("hook error")
		mh := &MiddlewareHooks{
			Before: []Middleware{
				func(ctx *Context) error {
					order = append(order, 1)
					return nil
				},
				func(ctx *Context) error {
					order = append(order, 2)
					return testErr
				},
				func(ctx *Context) error {
					order = append(order, 3)
					return nil
				},
			},
		}

		ctx := &Context{Path: "/test"}
		err := mh.RunBefore(ctx, logger)

		if err != testErr {
			t.Errorf("Expected testErr, got: %v", err)
		}
		if len(order) != 2 {
			t.Errorf("Expected 2 hooks to run, got %d", len(order))
		}
	})

	t.Run("returns nil for nil hooks", func(t *testing.T) {
		var mh *MiddlewareHooks
		ctx := &Context{Path: "/test"}
		err := mh.RunBefore(ctx, logger)

		if err != nil {
			t.Errorf("Expected nil, got: %v", err)
		}
	})
}

func TestMiddlewareHooks_RunAfter(t *testing.T) {
	logger := slog.Default()

	t.Run("runs all hooks even if one errors", func(t *testing.T) {
		var order []int
		mh := &MiddlewareHooks{
			After: []Middleware{
				func(ctx *Context) error {
					order = append(order, 1)
					return nil
				},
				func(ctx *Context) error {
					order = append(order, 2)
					return errors.New("error")
				},
				func(ctx *Context) error {
					order = append(order, 3)
					return nil
				},
			},
		}

		ctx := &Context{Path: "/test"}
		mh.RunAfter(ctx, logger)

		if len(order) != 3 {
			t.Errorf("Expected all 3 hooks to run, got %d", len(order))
		}
	})
}

func TestCreateMiddleware(t *testing.T) {
	called := false
	fn := func(ctx *Context) error {
		called = true
		return nil
	}

	middleware := CreateMiddleware(fn)
	_ = middleware(&Context{})

	if !called {
		t.Error("Middleware function was not called")
	}
}

func TestChainMiddleware(t *testing.T) {
	var order []int

	m1 := func(ctx *Context) error {
		order = append(order, 1)
		return nil
	}
	m2 := func(ctx *Context) error {
		order = append(order, 2)
		return nil
	}
	m3 := func(ctx *Context) error {
		order = append(order, 3)
		return nil
	}

	chained := ChainMiddleware(m1, m2, m3)
	_ = chained(&Context{})

	if len(order) != 3 || order[0] != 1 || order[1] != 2 || order[2] != 3 {
		t.Errorf("Chain ran in wrong order: %v", order)
	}
}

func TestSkipPaths(t *testing.T) {
	called := false
	middleware := func(ctx *Context) error {
		called = true
		return nil
	}

	skipped := SkipPaths(middleware, "/skip-me", "/also-skip")

	// Should skip
	_ = skipped(&Context{Path: "/skip-me"})
	if called {
		t.Error("Middleware should have been skipped")
	}

	// Should run
	_ = skipped(&Context{Path: "/run-me"})
	if !called {
		t.Error("Middleware should have been called")
	}
}

func TestOnlyPaths(t *testing.T) {
	callCount := 0
	middleware := func(ctx *Context) error {
		callCount++
		return nil
	}

	only := OnlyPaths(middleware, "/only-me", "/also-only")

	// Should skip
	_ = only(&Context{Path: "/skip-me"})
	if callCount != 0 {
		t.Error("Middleware should not have been called")
	}

	// Should run
	_ = only(&Context{Path: "/only-me"})
	if callCount != 1 {
		t.Error("Middleware should have been called")
	}
}

func TestRequireEmailDomain(t *testing.T) {
	middleware := RequireEmailDomain("example.com")

	tests := []struct {
		name      string
		path      string
		email     string
		wantError bool
	}{
		{"valid email on sign-up", "/sign-up", "test@example.com", false},
		{"invalid email on sign-up", "/sign-up", "test@other.com", true},
		{"skip non-sign-up paths", "/sign-in", "test@other.com", false},
		{"empty email", "/sign-up", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &Context{
				Path: tt.path,
				Body: map[string]any{"email": tt.email},
			}

			err := middleware(ctx)

			if tt.wantError && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestContext_Methods(t *testing.T) {
	t.Run("GetBodyString", func(t *testing.T) {
		ctx := &Context{
			Body: map[string]any{
				"email": "test@example.com",
				"count": 42, // not a string
			},
		}

		if got := ctx.GetBodyString("email"); got != "test@example.com" {
			t.Errorf("GetBodyString(email) = %s, want test@example.com", got)
		}
		if got := ctx.GetBodyString("count"); got != "" {
			t.Errorf("GetBodyString(count) = %s, want empty", got)
		}
		if got := ctx.GetBodyString("missing"); got != "" {
			t.Errorf("GetBodyString(missing) = %s, want empty", got)
		}
	})

	t.Run("GetBodyBool", func(t *testing.T) {
		ctx := &Context{
			Body: map[string]any{
				"enabled": true,
				"text":    "not a bool",
			},
		}

		if got := ctx.GetBodyBool("enabled"); !got {
			t.Error("GetBodyBool(enabled) = false, want true")
		}
		if got := ctx.GetBodyBool("text"); got {
			t.Error("GetBodyBool(text) = true, want false")
		}
	})

	t.Run("GetHeader", func(t *testing.T) {
		ctx := &Context{
			Headers: http.Header{
				"Content-Type": []string{"application/json"},
			},
		}

		if got := ctx.GetHeader("Content-Type"); got != "application/json" {
			t.Errorf("GetHeader = %s, want application/json", got)
		}
	})

	t.Run("GetQueryString", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test?foo=bar&baz=qux", nil)
		ctx := NewContext(nil, req, "/test")

		if got := ctx.GetQueryString("foo"); got != "bar" {
			t.Errorf("GetQueryString(foo) = %s, want bar", got)
		}
	})
}

func TestAPIError(t *testing.T) {
	t.Run("Error string", func(t *testing.T) {
		err := NewAPIError("BAD_REQUEST", "invalid email")
		if !strings.Contains(err.Error(), "BAD_REQUEST") {
			t.Errorf("Error() should contain status")
		}
		if !strings.Contains(err.Error(), "invalid email") {
			t.Errorf("Error() should contain message")
		}
	})

	t.Run("Error string with code", func(t *testing.T) {
		err := NewAPIErrorWithCode("BAD_REQUEST", "invalid email", "INVALID_EMAIL")
		if !strings.Contains(err.Error(), "INVALID_EMAIL") {
			t.Errorf("Error() should contain code")
		}
	})

	t.Run("HTTPStatus mapping", func(t *testing.T) {
		tests := []struct {
			status   string
			expected int
		}{
			{"BAD_REQUEST", 400},
			{"UNAUTHORIZED", 401},
			{"FORBIDDEN", 403},
			{"NOT_FOUND", 404},
			{"CONFLICT", 409},
			{"TOO_MANY_REQUESTS", 429},
			{"INTERNAL_ERROR", 500},
			{"UNKNOWN", 500},
		}

		for _, tt := range tests {
			err := NewAPIError(tt.status, "test")
			if got := err.HTTPStatus(); got != tt.expected {
				t.Errorf("HTTPStatus(%s) = %d, want %d", tt.status, got, tt.expected)
			}
		}
	})

	t.Run("WriteAPIError", func(t *testing.T) {
		w := httptest.NewRecorder()
		err := NewAPIError("BAD_REQUEST", "test error")

		WriteAPIError(w, err)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusBadRequest)
		}
		if ct := w.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %s, want application/json", ct)
		}
	})
}

func TestAsAPIError(t *testing.T) {
	t.Run("APIError passthrough", func(t *testing.T) {
		original := NewAPIError("FORBIDDEN", "access denied")
		result := AsAPIError(original)

		if result != original {
			t.Error("Should return same APIError")
		}
	})

	t.Run("wraps regular error", func(t *testing.T) {
		original := errors.New("database error")
		result := AsAPIError(original)

		if result.Status != "INTERNAL_ERROR" {
			t.Errorf("Status = %s, want INTERNAL_ERROR", result.Status)
		}
		if result.Message != "database error" {
			t.Errorf("Message = %s, want database error", result.Message)
		}
	})
}

func TestMiddlewareHooks_AddMethods(t *testing.T) {
	t.Run("AddBefore", func(t *testing.T) {
		mh := &MiddlewareHooks{}
		m1 := func(ctx *Context) error { return nil }
		m2 := func(ctx *Context) error { return nil }

		mh.AddBefore(m1, m2)

		if len(mh.Before) != 2 {
			t.Errorf("Before length = %d, want 2", len(mh.Before))
		}
	})

	t.Run("AddAfter", func(t *testing.T) {
		mh := &MiddlewareHooks{}
		m1 := func(ctx *Context) error { return nil }

		mh.AddAfter(m1)

		if len(mh.After) != 1 {
			t.Errorf("After length = %d, want 1", len(mh.After))
		}
	})

	t.Run("PrependBefore", func(t *testing.T) {
		var order []int
		mh := &MiddlewareHooks{
			Before: []Middleware{
				func(ctx *Context) error { order = append(order, 2); return nil },
			},
		}

		mh.PrependBefore(func(ctx *Context) error { order = append(order, 1); return nil })
		_ = mh.RunBefore(&Context{}, nil)

		if len(order) != 2 || order[0] != 1 || order[1] != 2 {
			t.Errorf("Prepend order = %v, want [1, 2]", order)
		}
	})
}
