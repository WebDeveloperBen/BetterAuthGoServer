package organization

import (
	"testing"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/organization/access"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	// Test default values
	if config.CreatorRole != "owner" {
		t.Errorf("CreatorRole = %q, want %q", config.CreatorRole, "owner")
	}

	if config.MembershipLimit != 100 {
		t.Errorf("MembershipLimit = %d, want %d", config.MembershipLimit, 100)
	}

	if config.InvitationExpiresIn != 48*time.Hour {
		t.Errorf("InvitationExpiresIn = %v, want %v", config.InvitationExpiresIn, 48*time.Hour)
	}

	if !config.CancelPendingInvitationsOnReInvite {
		t.Error("CancelPendingInvitationsOnReInvite should be true by default")
	}

	if config.Teams.Enabled {
		t.Error("Teams.Enabled should be false by default")
	}

	// Test default functions
	if !config.AllowUserToCreateOrganization("any-user") {
		t.Error("AllowUserToCreateOrganization should return true by default")
	}

	if config.OrganizationLimit("any-user") != 10 {
		t.Errorf("OrganizationLimit = %d, want %d", config.OrganizationLimit("any-user"), 10)
	}

	if config.Teams.MaximumTeams("any-org") != 10 {
		t.Errorf("MaximumTeams = %d, want %d", config.Teams.MaximumTeams("any-org"), 10)
	}

	if config.Teams.MaximumMembersPerTeam("any-team") != 50 {
		t.Errorf("MaximumMembersPerTeam = %d, want %d", config.Teams.MaximumMembersPerTeam("any-team"), 50)
	}
}

func TestWithAccessControl(t *testing.T) {
	ac, err := access.CreateDefaultAccessControl()
	if err != nil {
		t.Fatalf("Failed to create access control: %v", err)
	}

	adminRole, _ := ac.GetRole("admin")
	roles := map[string]*access.Role{"admin": adminRole}

	config := DefaultConfig()
	WithAccessControl(ac, roles)(&config)

	if config.AccessControl != ac {
		t.Error("AccessControl was not set correctly")
	}

	if config.Roles["admin"] != adminRole {
		t.Error("Roles was not set correctly")
	}
}

func TestWithAllowUserToCreateOrganization(t *testing.T) {
	config := DefaultConfig()

	// Custom function that only allows specific users
	allowFunc := func(userID string) bool {
		return userID == "allowed-user"
	}

	WithAllowUserToCreateOrganization(allowFunc)(&config)

	if !config.AllowUserToCreateOrganization("allowed-user") {
		t.Error("Should allow 'allowed-user'")
	}

	if config.AllowUserToCreateOrganization("other-user") {
		t.Error("Should not allow 'other-user'")
	}
}

func TestWithOrganizationLimit(t *testing.T) {
	config := DefaultConfig()

	limitFunc := func(userID string) int {
		if userID == "premium" {
			return 100
		}
		return 5
	}

	WithOrganizationLimit(limitFunc)(&config)

	if config.OrganizationLimit("premium") != 100 {
		t.Errorf("Premium user limit = %d, want %d", config.OrganizationLimit("premium"), 100)
	}

	if config.OrganizationLimit("free") != 5 {
		t.Errorf("Free user limit = %d, want %d", config.OrganizationLimit("free"), 5)
	}
}

func TestWithCreatorRole(t *testing.T) {
	config := DefaultConfig()

	WithCreatorRole("admin")(&config)

	if config.CreatorRole != "admin" {
		t.Errorf("CreatorRole = %q, want %q", config.CreatorRole, "admin")
	}
}

func TestWithMembershipLimit(t *testing.T) {
	config := DefaultConfig()

	WithMembershipLimit(500)(&config)

	if config.MembershipLimit != 500 {
		t.Errorf("MembershipLimit = %d, want %d", config.MembershipLimit, 500)
	}
}

func TestWithSendInvitationEmail(t *testing.T) {
	config := DefaultConfig()

	called := false
	sendFunc := func(invitation *Invitation, org *Organization) error {
		called = true
		return nil
	}

	WithSendInvitationEmail(sendFunc)(&config)

	if config.SendInvitationEmail == nil {
		t.Error("SendInvitationEmail should be set")
	}

	// Call the function to verify it works
	_ = config.SendInvitationEmail(&Invitation{}, &Organization{})
	if !called {
		t.Error("SendInvitationEmail function was not called")
	}
}

func TestWithInvitationExpiresIn(t *testing.T) {
	config := DefaultConfig()

	WithInvitationExpiresIn(7 * 24 * time.Hour)(&config)

	if config.InvitationExpiresIn != 7*24*time.Hour {
		t.Errorf("InvitationExpiresIn = %v, want %v", config.InvitationExpiresIn, 7*24*time.Hour)
	}
}

func TestWithCancelPendingInvitationsOnReInvite(t *testing.T) {
	config := DefaultConfig()

	WithCancelPendingInvitationsOnReInvite(false)(&config)

	if config.CancelPendingInvitationsOnReInvite {
		t.Error("CancelPendingInvitationsOnReInvite should be false")
	}
}

func TestWithTeams(t *testing.T) {
	config := DefaultConfig()

	teamsConfig := TeamsConfig{
		Enabled:               true,
		MaximumTeams:          func(orgID string) int { return 20 },
		MaximumMembersPerTeam: func(teamID string) int { return 100 },
		AllowRemovingAllTeams: true,
	}

	WithTeams(teamsConfig)(&config)

	if !config.Teams.Enabled {
		t.Error("Teams.Enabled should be true")
	}

	if config.Teams.MaximumTeams("any") != 20 {
		t.Errorf("MaximumTeams = %d, want %d", config.Teams.MaximumTeams("any"), 20)
	}

	if config.Teams.MaximumMembersPerTeam("any") != 100 {
		t.Errorf("MaximumMembersPerTeam = %d, want %d", config.Teams.MaximumMembersPerTeam("any"), 100)
	}

	if !config.Teams.AllowRemovingAllTeams {
		t.Error("AllowRemovingAllTeams should be true")
	}
}

func TestWithOrganizationHooks(t *testing.T) {
	config := DefaultConfig()

	beforeCreateCalled := false
	afterCreateCalled := false

	hooks := OrganizationHooks{
		BeforeCreateOrganization: func(org *Organization, userID string) error {
			beforeCreateCalled = true
			return nil
		},
		AfterCreateOrganization: func(org *Organization, member *Member, userID string) error {
			afterCreateCalled = true
			return nil
		},
	}

	WithOrganizationHooks(hooks)(&config)

	// Verify hooks are set
	if config.OrganizationHooks.BeforeCreateOrganization == nil {
		t.Error("BeforeCreateOrganization hook should be set")
	}

	if config.OrganizationHooks.AfterCreateOrganization == nil {
		t.Error("AfterCreateOrganization hook should be set")
	}

	// Call hooks to verify they work
	_ = config.OrganizationHooks.BeforeCreateOrganization(&Organization{}, "user-1")
	_ = config.OrganizationHooks.AfterCreateOrganization(&Organization{}, &Member{}, "user-1")

	if !beforeCreateCalled {
		t.Error("BeforeCreateOrganization hook was not called")
	}

	if !afterCreateCalled {
		t.Error("AfterCreateOrganization hook was not called")
	}
}

func TestMultipleOptions(t *testing.T) {
	config := DefaultConfig()

	// Apply multiple options
	options := []Option{
		WithCreatorRole("admin"),
		WithMembershipLimit(200),
		WithInvitationExpiresIn(24 * time.Hour),
		WithCancelPendingInvitationsOnReInvite(false),
		WithTeams(TeamsConfig{Enabled: true}),
	}

	for _, opt := range options {
		opt(&config)
	}

	if config.CreatorRole != "admin" {
		t.Errorf("CreatorRole = %q, want %q", config.CreatorRole, "admin")
	}

	if config.MembershipLimit != 200 {
		t.Errorf("MembershipLimit = %d, want %d", config.MembershipLimit, 200)
	}

	if config.InvitationExpiresIn != 24*time.Hour {
		t.Errorf("InvitationExpiresIn = %v, want %v", config.InvitationExpiresIn, 24*time.Hour)
	}

	if config.CancelPendingInvitationsOnReInvite {
		t.Error("CancelPendingInvitationsOnReInvite should be false")
	}

	if !config.Teams.Enabled {
		t.Error("Teams.Enabled should be true")
	}
}
