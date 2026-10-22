package oauth

import (
	"testing"
)

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

	plugin, err := NewPlugin(providers...)
	if err != nil {
		t.Fatalf("NewPlugin returned error: %v", err)
	}
	if plugin == nil {
		t.Fatal("NewPlugin returned nil")
	}

	if len(plugin.providers) != 2 {
		t.Errorf("NewPlugin providers count = %d, want 2", len(plugin.providers))
	}
}

func TestNewPlugin_Error_NoProviders(t *testing.T) {
	plugin, err := NewPlugin()
	if err == nil {
		t.Fatal("NewPlugin with no providers should return error")
	}
	if plugin != nil {
		t.Fatal("NewPlugin with no providers should return nil plugin")
	}
}

func TestPlugin_Routes_Disabled(t *testing.T) {
	// Plugin without initialized service should return nil routes
	plugin := &Plugin{}

	routes := plugin.Routes()
	if routes != nil {
		t.Errorf("Plugin.Routes() returned %d routes, want nil when disabled", len(routes))
	}
}

func TestPlugin_Routes_Enabled(t *testing.T) {
	// Plugin with initialized service should return routes
	mockStore := &mockStateStore{}
	service := NewService(mockStore, nil, nil)
	service.RegisterProvider(&mockProvider{name: "google"})

	plugin := &Plugin{
		service: service,
	}

	routes := plugin.Routes()
	if len(routes) != 3 {
		t.Errorf("Plugin.Routes() returned %d routes, want 3", len(routes))
	}

	// Check route paths
	expectedPaths := map[string]bool{
		"/oauth/providers":       false,
		"/oauth/":                false,
		"/oauth/{provider}/link": false,
	}

	for _, route := range routes {
		if route.Path == "/oauth/{provider}/link" && (route.Method != "POST" || !route.RequireAuth) {
			t.Errorf("link route must be POST and require auth, got %s RequireAuth=%t", route.Method, route.RequireAuth)
		}
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
