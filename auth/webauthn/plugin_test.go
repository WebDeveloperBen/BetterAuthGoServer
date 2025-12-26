package webauthn

import (
	"testing"
)

func TestPlugin_Name(t *testing.T) {
	p := NewPlugin()
	if p.Name() != PluginName {
		t.Errorf("Name() = %q, want %q", p.Name(), PluginName)
	}
}

func TestPlugin_Migrations(t *testing.T) {
	p := NewPlugin()
	migrations := p.Migrations()

	if len(migrations) != 2 {
		t.Fatalf("expected 2 migrations, got %d", len(migrations))
	}

	// Verify the types
	if _, ok := migrations[0].(*WebAuthnCredential); !ok {
		t.Error("expected first migration to be *WebAuthnCredential")
	}
	if _, ok := migrations[1].(*WebAuthnSession); !ok {
		t.Error("expected second migration to be *WebAuthnSession")
	}
}

func TestPlugin_IsEnabled(t *testing.T) {
	p := NewPlugin()

	// Before init, should not be enabled
	if p.IsEnabled() {
		t.Error("expected IsEnabled() to be false before Init()")
	}
}

func TestPlugin_Routes_WhenNotInitialized(t *testing.T) {
	p := NewPlugin()

	// Before init, should return nil routes
	routes := p.Routes()
	if routes != nil {
		t.Error("expected Routes() to return nil before Init()")
	}
}

func TestPlugin_Close(t *testing.T) {
	p := NewPlugin()

	// Close should not error even before initialization
	if err := p.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestPlugin_Service_BeforeInit(t *testing.T) {
	p := NewPlugin()

	// Service should be nil before Init
	if p.Service() != nil {
		t.Error("expected Service() to return nil before Init()")
	}
}

func TestNewPlugin_WithOptions(t *testing.T) {
	p := NewPlugin(
		WithRPID("example.com"),
		WithRPDisplayName("Test App"),
	)

	if p == nil {
		t.Fatal("expected plugin to not be nil")
	}

	// Options should be stored for later use during Init
	if len(p.opts) != 2 {
		t.Errorf("expected 2 options, got %d", len(p.opts))
	}
}
