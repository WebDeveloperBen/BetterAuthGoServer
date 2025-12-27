package deviceauth_test

import (
	"log/slog"
	"testing"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/deviceauth"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/token"
)

func TestPlugin_Name(t *testing.T) {
	p := deviceauth.NewPlugin()
	if p.Name() != "device-authorization" {
		t.Errorf("Name() = %q, want %q", p.Name(), "device-authorization")
	}
}

func TestPlugin_Init(t *testing.T) {
	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	t.Run("initializes successfully with valid context", func(t *testing.T) {
		tdb.truncateTables(t)

		auth := newMockAuthProvider()
		p := deviceauth.NewPlugin()

		hasher := token.NewHasher("test-secret-key-32-chars-long!!!")
		ctx := plugin.Context{
			DB:      tdb.DB,
			BaseURL: "https://example.com",
			Secret:  "test-secret-key-32-chars-long!!!",
			Auth:    auth,
			Hasher:  hasher,
			Logger:  slog.Default(),
		}

		err := p.Init(ctx)
		if err != nil {
			t.Fatalf("Init() failed: %v", err)
		}

		defer func() { _ = p.Close() }()

		// Should have routes after init
		routes := p.Routes()
		if len(routes) != 5 {
			t.Errorf("len(Routes()) = %d, want 5", len(routes))
		}
	})

	t.Run("returns nil routes without DB", func(t *testing.T) {
		auth := newMockAuthProvider()
		p := deviceauth.NewPlugin()

		ctx := plugin.Context{
			DB:      nil, // No DB
			BaseURL: "https://example.com",
			Auth:    auth,
			Logger:  slog.Default(),
		}

		err := p.Init(ctx)
		if err != nil {
			t.Fatalf("Init() should not error without DB")
		}

		routes := p.Routes()
		if routes != nil {
			t.Error("Routes() should be nil without DB")
		}
	})

	t.Run("returns nil routes without hasher", func(t *testing.T) {
		auth := newMockAuthProvider()
		p := deviceauth.NewPlugin()

		ctx := plugin.Context{
			DB:      tdb.DB,
			BaseURL: "https://example.com",
			Auth:    auth,
			Hasher:  nil, // No hasher
			Logger:  slog.Default(),
		}

		err := p.Init(ctx)
		if err != nil {
			t.Fatalf("Init() should not error without hasher")
		}

		routes := p.Routes()
		if routes != nil {
			t.Error("Routes() should be nil without hasher")
		}
	})

	t.Run("uses default verification URI from base URL", func(t *testing.T) {
		tdb.truncateTables(t)

		auth := newMockAuthProvider()
		p := deviceauth.NewPlugin() // No WithVerificationURI option

		hasher := token.NewHasher("test-secret-key-32-chars-long!!!")
		ctx := plugin.Context{
			DB:      tdb.DB,
			BaseURL: "https://myapp.com",
			Secret:  "test-secret-key-32-chars-long!!!",
			Auth:    auth,
			Hasher:  hasher,
			Logger:  slog.Default(),
		}

		err := p.Init(ctx)
		if err != nil {
			t.Fatalf("Init() failed: %v", err)
		}

		defer func() { _ = p.Close() }()

		// The verification URI should be derived from base URL
		// We can't directly check the config, but the plugin should work
		routes := p.Routes()
		if len(routes) != 5 {
			t.Errorf("len(Routes()) = %d, want 5", len(routes))
		}
	})
}

func TestPlugin_Routes(t *testing.T) {
	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	t.Run("returns correct routes", func(t *testing.T) {
		tdb.truncateTables(t)

		auth := newMockAuthProvider()
		p := createTestPlugin(t, tdb.DB, auth)
		defer func() { _ = p.Close() }()

		routes := p.Routes()

		expectedRoutes := []struct {
			method      string
			path        string
			requireAuth bool
		}{
			{"POST", "/device/code", false},
			{"POST", "/device/token", false},
			{"GET", "/device/verify", false},
			{"POST", "/device/approve", true},
			{"POST", "/device/deny", false},
		}

		if len(routes) != len(expectedRoutes) {
			t.Fatalf("len(Routes()) = %d, want %d", len(routes), len(expectedRoutes))
		}

		for i, expected := range expectedRoutes {
			if routes[i].Method != expected.method {
				t.Errorf("routes[%d].Method = %q, want %q", i, routes[i].Method, expected.method)
			}
			if routes[i].Path != expected.path {
				t.Errorf("routes[%d].Path = %q, want %q", i, routes[i].Path, expected.path)
			}
			if routes[i].RequireAuth != expected.requireAuth {
				t.Errorf("routes[%d].RequireAuth = %v, want %v", i, routes[i].RequireAuth, expected.requireAuth)
			}
		}
	})
}

func TestPlugin_Migrations(t *testing.T) {
	p := deviceauth.NewPlugin()

	migrations := p.Migrations()

	if len(migrations) != 1 {
		t.Errorf("len(Migrations()) = %d, want 1", len(migrations))
	}

	// Check that it's the DeviceCode model
	_, ok := migrations[0].(*deviceauth.DeviceCode)
	if !ok {
		t.Error("Migrations()[0] should be *DeviceCode")
	}
}

func TestPlugin_Close(t *testing.T) {
	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	t.Run("closes without error", func(t *testing.T) {
		tdb.truncateTables(t)

		auth := newMockAuthProvider()
		p := createTestPlugin(t, tdb.DB, auth)

		err := p.Close()
		if err != nil {
			t.Errorf("Close() should not error, got: %v", err)
		}
	})

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
	var _ plugin.MigrationsProvider = (*deviceauth.Plugin)(nil)
}
