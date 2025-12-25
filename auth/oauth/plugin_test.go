package oauth

import (
	"context"
	"net/http"
	"testing"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// mockAuthCore implements plugin.AuthCore for testing
type testAuthCore struct{}

func (m *testAuthCore) BaseURL() string { return "http://localhost:8080" }
func (m *testAuthCore) Secret() string  { return "test-secret" }
func (m *testAuthCore) GetPluginUser(ctx context.Context, userID string) (*plugin.User, error) {
	return nil, nil
}
func (m *testAuthCore) GetPluginUserByEmail(ctx context.Context, email string) (*plugin.User, error) {
	return nil, nil
}
func (m *testAuthCore) CreatePluginUser(ctx context.Context, req plugin.CreateUserRequest) (*plugin.User, error) {
	return nil, nil
}
func (m *testAuthCore) ValidateSessionToken(ctx context.Context, token string) (*plugin.Session, error) {
	return nil, nil
}
func (m *testAuthCore) CreateSessionForUser(ctx context.Context, userID string, r *http.Request) (*plugin.Session, error) {
	return nil, nil
}
func (m *testAuthCore) VerifyPassword(ctx context.Context, userID string, password string) (bool, error) {
	return true, nil
}

func TestPlugin_Name(t *testing.T) {
	plugin := &Plugin{}
	if plugin.Name() != PluginName {
		t.Errorf("Plugin.Name() = %s, want %s", plugin.Name(), PluginName)
	}
}

func TestNewPlugin(t *testing.T) {
	providers := []Provider{
		&mockProvider{name: "google"},
		&mockProvider{name: "github"},
	}

	plugin := NewPlugin(providers...)
	if plugin == nil {
		t.Fatal("NewPlugin returned nil")
	}

	if len(plugin.providers) != 2 {
		t.Errorf("NewPlugin providers count = %d, want 2", len(plugin.providers))
	}
}

func TestNewPlugin_Panic_NoProviders(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("NewPlugin with no providers should panic")
		}
	}()

	NewPlugin()
}

func TestPlugin_Routes(t *testing.T) {
	plugin := &Plugin{}

	routes := plugin.Routes()
	if len(routes) != 2 {
		t.Errorf("Plugin.Routes() returned %d routes, want 2", len(routes))
	}

	// Check route paths
	expectedPaths := map[string]bool{
		"/oauth/providers": false,
		"/oauth/":          false,
	}

	for _, route := range routes {
		if _, exists := expectedPaths[route.Path]; exists {
			expectedPaths[route.Path] = true
		}
	}

	for path, found := range expectedPaths {
		if !found {
			t.Errorf("Plugin.Routes() missing expected path: %s", path)
		}
	}
}

func TestPlugin_Close(t *testing.T) {
	plugin := &Plugin{}
	err := plugin.Close()
	if err != nil {
		t.Errorf("Plugin.Close() returned error: %v", err)
	}
}
