package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/config"
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
		config.WithSecret("super-secret-key-that-is-long-enough-for-testing"),
		config.WithBaseURL("http://localhost:8080"),
		config.WithPlugins(registry),
		config.WithRateLimit(false, 0, 0),
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
		config.WithSecret("super-secret-key-that-is-long-enough-for-testing"),
		config.WithBaseURL("http://localhost:8080"),
		config.WithPlugins(registry),
		config.WithRateLimit(false, 0, 0),
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
	// This test requires the HTTP router which is now in the handlers package.
	// Plugin routes are tested via e2e tests.
	t.Skip("Plugin routes are tested via handlers package and e2e tests")
}

func TestPluginIntegration_Middleware(t *testing.T) {
	// This test requires the HTTP router which is now in the handlers package.
	// Plugin middleware is tested via e2e tests.
	t.Skip("Plugin middleware is tested via handlers package and e2e tests")
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
		config.WithSecret("super-secret-key-that-is-long-enough-for-testing"),
		config.WithBaseURL("http://localhost:8080"),
		config.WithPlugins(registry),
		config.WithRateLimit(false, 0, 0),
		config.WithPasswordComplexity(false),
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
		config.WithSecret("super-secret-key-that-is-long-enough-for-testing"),
		config.WithBaseURL("http://localhost:8080"),
		config.WithPlugins(registry),
		config.WithRateLimit(false, 0, 0),
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
	cfg := config.DefaultConfig()

	config.WithPlugins(registry)(&cfg)

	if cfg.Plugins != registry {
		t.Error("WithPlugins did not set the registry")
	}
}
