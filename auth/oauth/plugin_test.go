package oauth

import (
	"context"
	"database/sql"
	"slices"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	oauthdb "github.com/webdeveloperben/BetterAuthGoServer/auth/oauth/db"
	coredb "github.com/webdeveloperben/BetterAuthGoServer/db"
	"github.com/webdeveloperben/BetterAuthGoServer/migrate"
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

func TestPlugin_ConfiguredProvidersSorted(t *testing.T) {
	service := NewService(&mockStateStore{}, nil, nil)
	service.RegisterProvider(&mockProvider{name: "zeta"})
	service.RegisterProvider(&mockProvider{name: "alpha"})
	plugin := &Plugin{service: service}

	if providers := plugin.ConfiguredProviders(); !slices.Equal(providers, []string{"alpha", "zeta"}) {
		t.Fatalf("ConfiguredProviders() = %v", providers)
	}
}

func TestPlugin_ListLinkedAccountsByUserIDs(t *testing.T) {
	ctx := context.Background()
	database, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	database.SetMaxOpenConns(1)
	if err := migrate.Run(ctx, database, migrate.DialectSQLite, migrate.WithPlugins(Migrations())); err != nil {
		t.Fatal(err)
	}
	coreStore, err := coredb.New(database, coredb.DialectSQLite)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	for _, user := range []*models.User{
		{ID: "directory-oauth-user-1", Email: "oauth-one@example.com", Role: "user", CreatedAt: now, UpdatedAt: now},
		{ID: "directory-oauth-user-2", Email: "oauth-two@example.com", Role: "user", CreatedAt: now, UpdatedAt: now},
	} {
		if err := coreStore.CreateUser(ctx, user); err != nil {
			t.Fatal(err)
		}
	}
	store, err := oauthdb.New(database, coredb.DialectSQLite)
	if err != nil {
		t.Fatal(err)
	}
	for _, account := range []*oauthdb.Account{
		{ID: "oauth-account-z", UserID: "directory-oauth-user-1", Provider: "github", ProviderAccountID: "private-github-id", AccessToken: "secret", CreatedAt: now.Add(time.Minute), UpdatedAt: now},
		{ID: "oauth-account-a", UserID: "directory-oauth-user-1", Provider: "google", ProviderAccountID: "private-google-id", AccessToken: "secret", CreatedAt: now, UpdatedAt: now},
		{ID: "oauth-account-b", UserID: "directory-oauth-user-2", Provider: "gitlab", ProviderAccountID: "private-gitlab-id", AccessToken: "secret", CreatedAt: now, UpdatedAt: now},
	} {
		if err := store.CreateAccount(ctx, account); err != nil {
			t.Fatal(err)
		}
	}

	plugin := &Plugin{store: store}
	accounts, err := plugin.ListLinkedAccountsByUserIDs(ctx, []string{"directory-oauth-user-2", "directory-oauth-user-1"})
	if err != nil {
		t.Fatal(err)
	}
	userAccounts := accounts["directory-oauth-user-1"]
	if len(userAccounts) != 2 || userAccounts[0].ID != "oauth-account-a" || userAccounts[1].ID != "oauth-account-z" {
		t.Fatalf("unexpected linked accounts: %#v", userAccounts)
	}
	if !slices.Equal([]string{userAccounts[0].Provider, userAccounts[1].Provider}, []string{"google", "github"}) {
		t.Fatalf("unexpected provider order: %#v", userAccounts)
	}
	if len(accounts["directory-oauth-user-2"]) != 1 {
		t.Fatalf("user 2 accounts = %#v", accounts["directory-oauth-user-2"])
	}
	if empty, err := plugin.ListLinkedAccountsByUserIDs(ctx, nil); err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("empty batch = %#v, error = %v", empty, err)
	}

	linked, err := plugin.ListLinkedAccounts(ctx, "directory-oauth-user-1")
	if err != nil || len(linked) != 2 {
		t.Fatalf("ListLinkedAccounts() = %#v, error = %v", linked, err)
	}
}

func TestPlugin_Close(t *testing.T) {
	plugin := &Plugin{}
	err := plugin.Close()
	if err != nil {
		t.Errorf("Plugin.Close() returned error: %v", err)
	}
}
