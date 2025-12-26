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

func TestWithPlugins(t *testing.T) {
	registry := plugin.NewRegistry(nil)
	cfg := config.DefaultConfig()

	config.WithPlugins(registry)(&cfg)

	if cfg.Plugins != registry {
		t.Error("WithPlugins did not set the registry")
	}
}
