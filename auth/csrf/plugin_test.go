package csrf

import (
	"testing"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

func TestNewPlugin(t *testing.T) {
	p := NewPlugin()

	if p == nil {
		t.Fatal("NewPlugin returned nil")
	}
}

func TestPlugin_Name(t *testing.T) {
	p := NewPlugin()

	if p.Name() != PluginName {
		t.Errorf("Name() = %s, want %s", p.Name(), PluginName)
	}
}

func TestPlugin_Init(t *testing.T) {
	p := NewPlugin(WithCookieName("custom_csrf"))

	ctx := plugin.Context{
		BaseURL: "https://example.com",
		Secret:  "test-secret",
	}

	err := p.Init(ctx)
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	if p.csrf == nil {
		t.Error("csrf should be initialized")
	}

	// Verify options were applied
	cfg := p.CSRF().Config()
	if cfg.CookieName != "custom_csrf" {
		t.Errorf("CookieName = %s, want custom_csrf", cfg.CookieName)
	}

	// Verify BaseURL from context was used
	if cfg.BaseURL != "https://example.com" {
		t.Errorf("BaseURL = %s, want https://example.com", cfg.BaseURL)
	}
}

func TestPlugin_Close(t *testing.T) {
	p := NewPlugin()
	p.Init(plugin.Context{})

	err := p.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestPlugin_Close_NotInitialized(t *testing.T) {
	p := NewPlugin()

	// Close before Init should not error
	err := p.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestPlugin_Middleware(t *testing.T) {
	p := NewPlugin()
	p.Init(plugin.Context{})

	mw := p.Middleware()
	if len(mw) != 1 {
		t.Fatalf("Middleware() returned %d items, want 1", len(mw))
	}

	if mw[0].Priority != MiddlewarePriority {
		t.Errorf("Priority = %d, want %d", mw[0].Priority, MiddlewarePriority)
	}

	if mw[0].Handler == nil {
		t.Error("Handler should not be nil")
	}
}

func TestPlugin_Middleware_NotInitialized(t *testing.T) {
	p := NewPlugin()

	mw := p.Middleware()
	if mw != nil {
		t.Errorf("Middleware() before Init should return nil, got %v", mw)
	}
}

func TestPlugin_CSRF(t *testing.T) {
	p := NewPlugin()
	p.Init(plugin.Context{})

	csrf := p.CSRF()
	if csrf == nil {
		t.Error("CSRF() should not be nil after Init")
	}
}

func TestPlugin_HeaderName(t *testing.T) {
	p := NewPlugin(WithHeaderName("X-Custom-Token"))
	p.Init(plugin.Context{})

	if p.HeaderName() != "X-Custom-Token" {
		t.Errorf("HeaderName() = %s, want X-Custom-Token", p.HeaderName())
	}
}

func TestPlugin_HeaderName_BeforeInit(t *testing.T) {
	p := NewPlugin()

	// Before init, should return default
	if p.HeaderName() != "X-CSRF-Token" {
		t.Errorf("HeaderName() = %s, want X-CSRF-Token", p.HeaderName())
	}
}

func TestPlugin_ImplementsInterfaces(t *testing.T) {
	p := NewPlugin()

	// Check Plugin interface
	var _ plugin.Plugin = p

	// Check MiddlewareProvider interface
	var _ plugin.MiddlewareProvider = p
}
