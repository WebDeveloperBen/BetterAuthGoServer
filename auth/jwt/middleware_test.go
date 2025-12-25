package jwt

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

func TestGetJWTClaims(t *testing.T) {
	ctx := context.Background()

	// Test with no claims in context
	claims, ok := GetJWTClaims(ctx)
	if ok || claims != nil {
		t.Error("Expected no claims in empty context")
	}

	// Test with claims in context
	testClaims := &Claims{}
	ctxWithClaims := context.WithValue(ctx, jwtClaimsKey, testClaims)

	claims, ok = GetJWTClaims(ctxWithClaims)
	if !ok || claims != testClaims {
		t.Error("Expected to retrieve claims from context")
	}

	// Test with wrong type in context
	ctxWithWrongType := context.WithValue(ctx, jwtClaimsKey, "not claims")
	claims, ok = GetJWTClaims(ctxWithWrongType)
	if ok || claims != nil {
		t.Error("Expected type assertion to fail")
	}
}

func TestGetJWTUser(t *testing.T) {
	ctx := context.Background()

	// Test with no user in context
	user, ok := GetJWTUser(ctx)
	if ok || user != nil {
		t.Error("Expected no user in empty context")
	}

	// Test with user in context
	testUser := &plugin.User{ID: "test-user"}
	ctxWithUser := context.WithValue(ctx, jwtUserKey, testUser)

	user, ok = GetJWTUser(ctxWithUser)
	if !ok || user != testUser {
		t.Error("Expected to retrieve user from context")
	}

	// Test with wrong type in context
	ctxWithWrongType := context.WithValue(ctx, jwtUserKey, "not user")
	user, ok = GetJWTUser(ctxWithWrongType)
	if ok || user != nil {
		t.Error("Expected type assertion to fail")
	}
}

func TestJWTAuthMiddleware_NoToken(t *testing.T) {
	// Create a minimal plugin for testing
	p := &Plugin{}

	middleware := p.jwtAuthMiddleware()
	called := false
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		// Check that no JWT context was added
		claims, ok := GetJWTClaims(r.Context())
		if ok || claims != nil {
			t.Error("Expected no JWT claims in context")
		}
		user, ok := GetJWTUser(r.Context())
		if ok || user != nil {
			t.Error("Expected no JWT user in context")
		}
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("Handler should have been called")
	}
}

func TestJWTAuthMiddleware_InvalidToken(t *testing.T) {
	// Create a plugin with a service
	config := DefaultConfig()
	config.Secret = "test-secret-key-that-is-long-enough-for-jwt!!!"
	service, err := NewService(config)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	p := &Plugin{service: service}

	middleware := p.jwtAuthMiddleware()
	called := false
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		// Check that no JWT context was added due to invalid token
		claims, ok := GetJWTClaims(r.Context())
		if ok || claims != nil {
			t.Error("Expected no JWT claims in context for invalid token")
		}
		user, ok := GetJWTUser(r.Context())
		if ok || user != nil {
			t.Error("Expected no JWT user in context for invalid token")
		}
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer invalid.jwt.token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("Handler should have been called despite invalid token")
	}
}

func TestJWTAuthMiddleware_MissingBearer(t *testing.T) {
	// Create a plugin with a service
	config := DefaultConfig()
	config.Secret = "test-secret-key-that-is-long-enough-for-jwt!!!"
	service, err := NewService(config)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	p := &Plugin{service: service}

	middleware := p.jwtAuthMiddleware()
	called := false
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		// Check that no JWT context was added due to missing Bearer prefix
		claims, ok := GetJWTClaims(r.Context())
		if ok || claims != nil {
			t.Error("Expected no JWT claims in context for missing Bearer")
		}
		user, ok := GetJWTUser(r.Context())
		if ok || user != nil {
			t.Error("Expected no JWT user in context for missing Bearer")
		}
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "invalid.jwt.token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("Handler should have been called despite missing Bearer prefix")
	}
}

func TestPlugin_MiddlewareIntegration(t *testing.T) {
	// Create plugin and test middleware integration
	p := NewPlugin()

	// Test middleware before init
	middleware := p.Middleware()
	if len(middleware) != 1 {
		t.Errorf("Expected 1 middleware, got %d", len(middleware))
	}

	if middleware[0].Priority != MiddlewarePriority {
		t.Errorf("Expected priority %d, got %d", MiddlewarePriority, middleware[0].Priority)
	}
}
