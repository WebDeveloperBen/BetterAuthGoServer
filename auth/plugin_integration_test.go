package auth

import (
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

// Note: ValidatorProvider tests have been removed since SignUp/SignIn are now
// provided by the password plugin. Validator integration is tested via e2e tests
// that exercise the password plugin's HTTP endpoints.

func TestPluginIntegration_ValidateSignUp(t *testing.T) {
	// SignUp is now handled by the password plugin, not core auth.
	// Validator integration is tested via e2e tests that exercise
	// the password plugin's HTTP endpoints.
	t.Skip("SignUp moved to password plugin - validator integration tested via e2e")
}

func TestPluginIntegration_ValidateSignIn(t *testing.T) {
	// SignIn is now handled by the password plugin, not core auth.
	// Validator integration is tested via e2e tests that exercise
	// the password plugin's HTTP endpoints.
	t.Skip("SignIn moved to password plugin - validator integration tested via e2e")
}

func TestWithPlugins(t *testing.T) {
	registry := plugin.NewRegistry(nil)
	cfg := config.DefaultConfig()

	config.WithPlugins(registry)(&cfg)

	if cfg.Plugins != registry {
		t.Error("WithPlugins did not set the registry")
	}
}
