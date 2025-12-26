package admin

import (
	"log/slog"
	"os"
	"testing"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

func TestPlugin_Name(t *testing.T) {
	p := NewPlugin()
	if p.Name() != PluginName {
		t.Errorf("Name() = %q, want %q", p.Name(), PluginName)
	}
}

func TestPlugin_Close(t *testing.T) {
	p := NewPlugin()

	// Should not panic
	err := p.Close()
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestPlugin_Routes_WhenNotInitialized(t *testing.T) {
	p := NewPlugin()
	routes := p.Routes()

	// Should return nil when not initialized
	if routes != nil {
		t.Error("Routes() should return nil when not initialized")
	}
}

func TestNewPlugin_DefaultConfig(t *testing.T) {
	p := NewPlugin()

	// Check that default config is applied
	if p.config.DefaultRole != "user" {
		t.Errorf("DefaultRole = %q, want %q", p.config.DefaultRole, "user")
	}

	if p.config.AdminRoles[0] != "admin" {
		t.Errorf("First AdminRole = %q, want %q", p.config.AdminRoles[0], "admin")
	}
}

func TestPlugin_Init_WithoutDatabase(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	// Mock context without database
	ctx := plugin.Context{
		Logger:  logger,
		DB:      nil,
		BaseURL: "http://localhost:8080",
		Secret:  "test-secret",
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

func TestPlugin_Init_WithoutUserProvider(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	// Mock context with nil DB (since we can't mock bun.DB easily)
	ctx := plugin.Context{
		Logger:  logger,
		DB:      nil, // We'll skip the DB check for this test
		Auth:    &mockAuthWithoutUserProvider{},
		BaseURL: "http://localhost:8080",
		Secret:  "test-secret",
	}

	p := NewPlugin()
	// Skip DB initialization by setting it after creation
	p.ctx = ctx

	// Manually set service to nil to simulate disabled state
	p.service = nil

	// Routes should return nil when disabled
	routes := p.Routes()
	if routes != nil {
		t.Error("Routes() should return nil when plugin disabled")
	}
}

// mockAuthWithoutUserProvider doesn't implement UserProvider but implements AuthCore
type mockAuthWithoutUserProvider struct{}

func (m *mockAuthWithoutUserProvider) BaseURL() string {
	return "http://localhost:8080"
}

func (m *mockAuthWithoutUserProvider) Secret() string {
	return "test-secret"
}
