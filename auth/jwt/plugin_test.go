package jwt

import (
	"testing"
)

func TestPlugin_Basic(t *testing.T) {
	// Create a JWT plugin
	p := NewPlugin(
		WithAlgorithm(AlgorithmHS256),
		WithAccessTTL(15*60),       // 15 minutes
		WithRefreshTTL(7*24*60*60), // 7 days
	)

	// Test plugin name
	if p.Name() != PluginName {
		t.Errorf("Name() = %s, want %s", p.Name(), PluginName)
	}

	// Test routes (before init)
	routes := p.Routes()
	if len(routes) != 4 { // token, token/refresh, token/revoke, token/introspect
		t.Errorf("Routes() returned %d routes, want 4", len(routes))
	}

	// Test middleware (before init)
	middleware := p.Middleware()
	if len(middleware) != 1 {
		t.Errorf("Middleware() returned %d middleware, want 1", len(middleware))
	}

	// Plugin doesn't provide migrations (uses memory blocklist by default)
}
