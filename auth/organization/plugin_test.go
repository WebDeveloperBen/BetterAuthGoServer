package organization

import (
	"testing"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

func TestPlugin_Name(t *testing.T) {
	p := NewPlugin()
	if p.Name() != PluginName {
		t.Errorf("Name() = %q, want %q", p.Name(), PluginName)
	}
}

func TestNewPlugin_DefaultConfig(t *testing.T) {
	p := NewPlugin()

	// Verify default config values
	if p.config.CreatorRole != "owner" {
		t.Errorf("CreatorRole = %q, want %q", p.config.CreatorRole, "owner")
	}

	if p.config.MembershipLimit != 100 {
		t.Errorf("MembershipLimit = %d, want %d", p.config.MembershipLimit, 100)
	}

	if p.config.InvitationExpiresIn != 48*time.Hour {
		t.Errorf("InvitationExpiresIn = %v, want %v", p.config.InvitationExpiresIn, 48*time.Hour)
	}

	if p.config.Teams.Enabled {
		t.Error("Teams.Enabled should be false by default")
	}
}

func TestNewPlugin_WithOptions(t *testing.T) {
	p := NewPlugin(
		WithMembershipLimit(50),
		WithCreatorRole("admin"),
		WithInvitationExpiresIn(24*time.Hour),
		WithTeams(TeamsConfig{Enabled: true}),
	)

	if p.config.MembershipLimit != 50 {
		t.Errorf("MembershipLimit = %d, want %d", p.config.MembershipLimit, 50)
	}

	if p.config.CreatorRole != "admin" {
		t.Errorf("CreatorRole = %q, want %q", p.config.CreatorRole, "admin")
	}

	if p.config.InvitationExpiresIn != 24*time.Hour {
		t.Errorf("InvitationExpiresIn = %v, want %v", p.config.InvitationExpiresIn, 24*time.Hour)
	}

	if !p.config.Teams.Enabled {
		t.Error("Teams.Enabled should be true")
	}
}

func TestPlugin_Init_WithoutDatabase(t *testing.T) {
	ctx := plugin.Context{
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

func TestPlugin_Init_WithoutAuth(t *testing.T) {
	ctx := plugin.Context{
		BaseURL: "http://localhost:8080",
		Secret:  "test-secret",
		// DB is nil, Auth is nil
	}

	p := NewPlugin()
	err := p.Init(ctx)

	if err != nil {
		t.Errorf("Init() should not error, got: %v", err)
	}

	// Plugin should be disabled
	routes := p.Routes()
	if routes != nil {
		t.Error("Routes() should return nil when plugin disabled")
	}
}

func TestPlugin_Close(t *testing.T) {
	p := NewPlugin()

	err := p.Close()
	if err != nil {
		t.Errorf("Close() should not error, got: %v", err)
	}
}

func TestPlugin_Routes_WhenDisabled(t *testing.T) {
	p := NewPlugin()

	// Without initialization, routes should be nil
	routes := p.Routes()
	if routes != nil {
		t.Error("Routes() should return nil when plugin not initialized")
	}
}

func TestPlugin_Middleware_WhenDisabled(t *testing.T) {
	p := NewPlugin()

	// Without initialization, middleware should still work
	middlewares := p.Middleware()
	if len(middlewares) != 1 {
		t.Errorf("len(middlewares) = %d, want %d", len(middlewares), 1)
	}
}

func TestPlugin_Migrations_Basic(t *testing.T) {
	p := NewPlugin()

	migrations := p.Migrations()

	// Should include: Organization, Member, Invitation
	// Teams are disabled by default, so Team and TeamMember should not be included
	// Note: SessionExtension is added via ALTER TABLE in Init(), not here
	expectedCount := 3

	if len(migrations) != expectedCount {
		t.Errorf("len(migrations) = %d, want %d", len(migrations), expectedCount)
	}
}

func TestPlugin_Migrations_WithTeams(t *testing.T) {
	p := NewPlugin(
		WithTeams(TeamsConfig{Enabled: true}),
	)

	migrations := p.Migrations()

	// Should include: Organization, Member, Invitation, Team, TeamMember
	// Note: SessionExtension is added via ALTER TABLE in Init(), not here
	expectedCount := 5

	if len(migrations) != expectedCount {
		t.Errorf("len(migrations) = %d, want %d", len(migrations), expectedCount)
	}
}

func TestPlugin_ImplementsInterfaces(t *testing.T) {
	p := NewPlugin()

	// Test that plugin implements required interfaces
	var _ plugin.Plugin = p
	var _ plugin.RoutesProvider = p
	var _ plugin.MiddlewareProvider = p
	var _ plugin.MigrationsProvider = p
}

func TestPlugin_AccessControlInitialization(t *testing.T) {
	// When no access control is provided, it should be created with defaults
	p := NewPlugin()

	// Access control is nil before Init
	if p.config.AccessControl != nil {
		t.Error("AccessControl should be nil before Init")
	}
}

func TestPlugin_OrganizationContextMiddleware(t *testing.T) {
	p := NewPlugin()

	middlewares := p.Middleware()
	if len(middlewares) == 0 {
		t.Fatal("Expected at least one middleware")
	}

	// Verify middleware priority
	if middlewares[0].Priority != 25 {
		t.Errorf("Middleware priority = %d, want %d", middlewares[0].Priority, 25)
	}

	if middlewares[0].Handler == nil {
		t.Error("Middleware handler should not be nil")
	}
}

func TestPluginName_Constant(t *testing.T) {
	if PluginName != "organization" {
		t.Errorf("PluginName = %q, want %q", PluginName, "organization")
	}
}
