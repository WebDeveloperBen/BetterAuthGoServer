package anonymous

import (
	"log/slog"
	"testing"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

func TestPlugin_Name(t *testing.T) {
	p := NewPlugin()
	if p.Name() != PluginName {
		t.Errorf("Name() = %q, want %q", p.Name(), PluginName)
	}
}

func TestPluginName_Constant(t *testing.T) {
	if PluginName != "anonymous" {
		t.Errorf("PluginName = %q, want %q", PluginName, "anonymous")
	}
}

func TestNewPlugin_DefaultConfig(t *testing.T) {
	p := NewPlugin()

	// Options are stored but config isn't built until Init
	if len(p.opts) != 0 {
		t.Errorf("len(opts) = %d, want %d", len(p.opts), 0)
	}
}

func TestNewPlugin_WithOptions(t *testing.T) {
	p := NewPlugin(
		WithEmailDomain("test.local"),
		WithAnonymousUserTTL(24*time.Hour),
		WithDisableDeleteAnonymousUser(),
	)

	// Options are stored
	if len(p.opts) != 3 {
		t.Errorf("len(opts) = %d, want %d", len(p.opts), 3)
	}
}

func TestPlugin_Init_WithoutDatabase(t *testing.T) {
	ctx := plugin.Context{
		BaseURL: "http://localhost:8080",
		Secret:  "test-secret",
		Logger:  slog.Default(),
		// DB is nil
	}

	p := NewPlugin()
	err := p.Init(ctx)

	// Should not error, but should disable plugin
	if err != nil {
		t.Errorf("Init() should not error without database, got: %v", err)
	}

	// Routes should return nil when disabled
	routes := p.Routes()
	if routes != nil {
		t.Error("Routes() should return nil when plugin disabled")
	}
}

func TestPlugin_Init_WithoutAuth(t *testing.T) {
	ctx := plugin.Context{
		BaseURL: "http://localhost:8080",
		Secret:  "test-secret",
		Logger:  slog.Default(),
		// Auth is nil
	}

	p := NewPlugin()
	err := p.Init(ctx)

	if err != nil {
		t.Errorf("Init() should not error, got: %v", err)
	}

	// Plugin should be disabled
	routes := p.Routes()
	if routes != nil {
		t.Error("Routes() should return nil when plugin disabled")
	}
}

func TestPlugin_Close(t *testing.T) {
	p := NewPlugin()

	err := p.Close()
	if err != nil {
		t.Errorf("Close() should not error, got: %v", err)
	}
}

func TestPlugin_Routes_WhenDisabled(t *testing.T) {
	p := NewPlugin()

	// Without initialization, routes should be nil
	routes := p.Routes()
	if routes != nil {
		t.Error("Routes() should return nil when plugin not initialized")
	}
}

func TestPlugin_Middleware_WhenDisabled(t *testing.T) {
	p := NewPlugin()

	// Without initialization, middleware should be nil
	middlewares := p.Middleware()
	if middlewares != nil {
		t.Error("Middleware() should return nil when plugin not initialized")
	}
}

func TestPlugin_ImplementsInterfaces(t *testing.T) {
	p := NewPlugin()

	// Test that plugin implements required interfaces
	var _ plugin.Plugin = p
	var _ plugin.RoutesProvider = p
	var _ plugin.MiddlewareProvider = p
}

func TestMiddlewarePriority_Constant(t *testing.T) {
	if MiddlewarePriority != 5 {
		t.Errorf("MiddlewarePriority = %d, want %d", MiddlewarePriority, 5)
	}
}
