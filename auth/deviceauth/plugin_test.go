package deviceauth_test

import (
	"log/slog"
	"testing"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/deviceauth"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

func TestPlugin_Name(t *testing.T) {
	p := deviceauth.NewPlugin()
	if p.Name() != "device-authorization" {
		t.Errorf("Name() = %q, want %q", p.Name(), "device-authorization")
	}
}

func TestPlugin_Init(t *testing.T) {
	t.Run("returns nil routes without store", func(t *testing.T) {
		auth := newMockAuthProvider()
		p := deviceauth.NewPlugin()

		ctx := plugin.Context{
			Store:   nil, // No Store
			BaseURL: "https://example.com",
			Auth:    auth,
			Logger:  slog.Default(),
		}

		err := p.Init(ctx)
		if err != nil {
			t.Fatalf("Init() should not error without store: %v", err)
		}

		routes := p.Routes()
		if routes != nil {
			t.Error("Routes() should be nil without store")
		}
	})

	t.Run("returns nil routes without hasher", func(t *testing.T) {
		auth := newMockAuthProvider()
		p := deviceauth.NewPlugin()

		ctx := plugin.Context{
			Store:   nil, // No store yet - hasher check happens first
			BaseURL: "https://example.com",
			Auth:    auth,
			Hasher:  nil, // No hasher
			Logger:  slog.Default(),
		}

		err := p.Init(ctx)
		if err != nil {
			t.Fatalf("Init() should not error without hasher: %v", err)
		}

		routes := p.Routes()
		if routes != nil {
			t.Error("Routes() should be nil without hasher")
		}
	})
}

func TestPlugin_Close(t *testing.T) {
	t.Run("closes without init", func(t *testing.T) {
		p := deviceauth.NewPlugin()

		err := p.Close()
		if err != nil {
			t.Errorf("Close() should not error without init, got: %v", err)
		}
	})
}

func TestPlugin_InterfaceCompliance(t *testing.T) {
	var _ plugin.Plugin = (*deviceauth.Plugin)(nil)
	var _ plugin.RoutesProvider = (*deviceauth.Plugin)(nil)
}
