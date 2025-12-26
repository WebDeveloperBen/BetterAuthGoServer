package ratelimit

import (
	"testing"
	"time"

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
	p := NewPlugin(WithLimit(50, 2*time.Minute))

	ctx := plugin.Context{
		BaseURL: "http://localhost:3000",
		Secret:  "test-secret",
	}

	err := p.Init(ctx)
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	if p.limiter == nil {
		t.Error("limiter should be initialized")
	}

	// Verify options were applied
	cfg := p.Limiter().Config()
	if cfg.MaxRequests != 50 {
		t.Errorf("MaxRequests = %d, want 50", cfg.MaxRequests)
	}
	if cfg.Window != 2*time.Minute {
		t.Errorf("Window = %v, want %v", cfg.Window, 2*time.Minute)
	}
}

func TestPlugin_Close(t *testing.T) {
	p := NewPlugin()
	_ = p.Init(plugin.Context{})

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
	_ = p.Init(plugin.Context{})

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

func TestPlugin_Limiter(t *testing.T) {
	p := NewPlugin()
	_ = p.Init(plugin.Context{})

	limiter := p.Limiter()
	if limiter == nil {
		t.Error("Limiter() should not be nil after Init")
	}
}

func TestPlugin_ImplementsInterfaces(t *testing.T) {
	p := NewPlugin()

	// Check Plugin interface
	var _ plugin.Plugin = p

	// Check MiddlewareProvider interface
	var _ plugin.MiddlewareProvider = p
}
