package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// testPlugin is a simple plugin for testing
type testPlugin struct {
	initCalled  bool
	closeCalled bool
	routes      []plugin.Route
	middleware  []func(http.Handler) http.Handler
}

func (p *testPlugin) Name() string { return "test-plugin" }

func (p *testPlugin) Init(ctx plugin.Context) error {
	p.initCalled = true
	return nil
}

func (p *testPlugin) Close() error {
	p.closeCalled = true
	return nil
}

func (p *testPlugin) Routes() []plugin.Route {
	return p.routes
}

func (p *testPlugin) Middleware() []func(http.Handler) http.Handler {
	return p.middleware
}

func TestPluginIntegration_Init(t *testing.T) {
	store := newMockStoreForMiddleware()
	registry := plugin.NewRegistry(nil)
	tp := &testPlugin{}
	registry.Register(tp)

	a, err := New(store,
		WithSecret("super-secret-key-that-is-long-enough-for-testing"),
		WithBaseURL("http://localhost:8080"),
		WithPlugins(registry),
		WithRateLimit(false, 0, 0),
	)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer a.Close()

	if !tp.initCalled {
		t.Error("Plugin Init was not called")
	}
}

func TestPluginIntegration_Close(t *testing.T) {
	store := newMockStoreForMiddleware()
	registry := plugin.NewRegistry(nil)
	tp := &testPlugin{}
	registry.Register(tp)

	a, err := New(store,
		WithSecret("super-secret-key-that-is-long-enough-for-testing"),
		WithBaseURL("http://localhost:8080"),
		WithPlugins(registry),
		WithRateLimit(false, 0, 0),
	)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	a.Close()

	if !tp.closeCalled {
		t.Error("Plugin Close was not called")
	}
}

func TestPluginIntegration_Routes(t *testing.T) {
	store := newMockStoreForMiddleware()
	registry := plugin.NewRegistry(nil)

	handlerCalled := false
	tp := &testPlugin{
		routes: []plugin.Route{
			{
				Method:      "GET",
				Path:        "/plugin/test",
				RequireAuth: false,
				Handler: func(w http.ResponseWriter, r *http.Request) {
					handlerCalled = true
					w.WriteHeader(http.StatusOK)
				},
			},
		},
	}
	registry.Register(tp)

	a, err := New(store,
		WithSecret("super-secret-key-that-is-long-enough-for-testing"),
		WithBaseURL("http://localhost:8080"),
		WithPlugins(registry),
		WithRateLimit(false, 0, 0),
		WithCSRF(false),
	)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer a.Close()

	handler := a.Handler()
	req := httptest.NewRequest("GET", "/plugin/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if !handlerCalled {
		t.Error("Plugin route handler was not called")
	}
}

func TestPluginIntegration_Middleware(t *testing.T) {
	store := newMockStoreForMiddleware()
	registry := plugin.NewRegistry(nil)

	middlewareCalled := false
	tp := &testPlugin{
		middleware: []func(http.Handler) http.Handler{
			func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					middlewareCalled = true
					next.ServeHTTP(w, r)
				})
			},
		},
	}
	registry.Register(tp)

	a, err := New(store,
		WithSecret("super-secret-key-that-is-long-enough-for-testing"),
		WithBaseURL("http://localhost:8080"),
		WithPlugins(registry),
		WithRateLimit(false, 0, 0),
		WithCSRF(false),
	)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer a.Close()

	handler := a.Handler()
	req := httptest.NewRequest("GET", "/oauth/providers", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if !middlewareCalled {
		t.Error("Plugin middleware was not called")
	}
}

// validatorPlugin implements ValidatorProvider
type validatorPlugin struct {
	testPlugin
	signUpError error
	signInError error
}

func (p *validatorPlugin) ValidateSignUp(ctx context.Context, email, password, name string) error {
	return p.signUpError
}

func (p *validatorPlugin) ValidateSignIn(ctx context.Context, email string) error {
	return p.signInError
}

func TestPluginIntegration_ValidateSignUp(t *testing.T) {
	store := newMockStoreForMiddleware()
	registry := plugin.NewRegistry(nil)

	expectedErr := errors.New("signup blocked by plugin")
	vp := &validatorPlugin{signUpError: expectedErr}
	registry.Register(vp)

	a, err := New(store,
		WithSecret("super-secret-key-that-is-long-enough-for-testing"),
		WithBaseURL("http://localhost:8080"),
		WithPlugins(registry),
		WithRateLimit(false, 0, 0),
		WithPasswordComplexity(false),
	)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer a.Close()

	_, _, err = a.SignUp(context.Background(), SignUpRequest{
		Email:    "test@example.com",
		Password: "password123",
		Name:     "Test",
	}, nil)

	if err != expectedErr {
		t.Errorf("Expected error %v, got %v", expectedErr, err)
	}
}

func TestPluginIntegration_ValidateSignIn(t *testing.T) {
	store := newMockStoreForMiddleware()
	registry := plugin.NewRegistry(nil)

	expectedErr := errors.New("signin blocked by plugin")
	vp := &validatorPlugin{signInError: expectedErr}
	registry.Register(vp)

	a, err := New(store,
		WithSecret("super-secret-key-that-is-long-enough-for-testing"),
		WithBaseURL("http://localhost:8080"),
		WithPlugins(registry),
		WithRateLimit(false, 0, 0),
	)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer a.Close()

	_, _, err = a.SignIn(context.Background(), "test@example.com", "password", nil)

	if err != expectedErr {
		t.Errorf("Expected error %v, got %v", expectedErr, err)
	}
}

func TestWithPlugins(t *testing.T) {
	registry := plugin.NewRegistry(nil)
	cfg := DefaultConfig()

	WithPlugins(registry)(&cfg)

	if cfg.Plugins != registry {
		t.Error("WithPlugins did not set the registry")
	}
}
