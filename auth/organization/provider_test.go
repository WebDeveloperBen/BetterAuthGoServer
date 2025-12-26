package organization_test

import (
	"context"
	"testing"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/organization"
)

func TestService_ImplementsOrganizationOperations(t *testing.T) {
	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	service := createTestService(t, tdb.DB, organization.WithTeams(organization.TeamsConfig{Enabled: true}))

	// Verify service implements the interface
	var _ organization.OrganizationOperations = service
}

func TestOrganizationOperations_OrganizationCRUD(t *testing.T) {
	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	var ops organization.OrganizationOperations = createTestService(t, tdb.DB)

	t.Run("CreateOrganization", func(t *testing.T) {
		tdb.truncateTables(t)
		user := tdb.createTestUser(t, "user-1", "user@example.com", "User")

		org, err := ops.CreateOrganization(ctx, "Test Org", "test-org", user.ID, nil)
		if err != nil {
			t.Fatalf("CreateOrganization failed: %v", err)
		}

		if org == nil {
			t.Fatal("Organization should not be nil")
		}

		if org.Name != "Test Org" {
			t.Errorf("Name = %q, want %q", org.Name, "Test Org")
		}
	})

	t.Run("GetOrganization", func(t *testing.T) {
		tdb.truncateTables(t)
		user := tdb.createTestUser(t, "user-1", "user@example.com", "User")

		created, _ := ops.CreateOrganization(ctx, "Test Org", "test-org", user.ID, nil)

		org, err := ops.GetOrganization(ctx, created.ID)
		if err != nil {
			t.Fatalf("GetOrganization failed: %v", err)
		}

		if org.ID != created.ID {
			t.Errorf("ID = %q, want %q", org.ID, created.ID)
		}
	})

	t.Run("GetOrganizationBySlug", func(t *testing.T) {
		tdb.truncateTables(t)
		user := tdb.createTestUser(t, "user-1", "user@example.com", "User")

		created, _ := ops.CreateOrganization(ctx, "Test Org", "my-slug", user.ID, nil)

		org, err := ops.GetOrganizationBySlug(ctx, "my-slug")
		if err != nil {
			t.Fatalf("GetOrganizationBySlug failed: %v", err)
		}

		if org.ID != created.ID {
			t.Errorf("ID = %q, want %q", org.ID, created.ID)
		}
	})

	t.Run("UpdateOrganization", func(t *testing.T) {
		tdb.truncateTables(t)
		user := tdb.createTestUser(t, "user-1", "user@example.com", "User")

		created, _ := ops.CreateOrganization(ctx, "Old Name", "old-slug", user.ID, nil)

		updated, err := ops.UpdateOrganization(ctx, created.ID, map[string]any{"name": "New Name"})
		if err != nil {
			t.Fatalf("UpdateOrganization failed: %v", err)
		}

		if updated.Name != "New Name" {
			t.Errorf("Name = %q, want %q", updated.Name, "New Name")
		}
	})

	t.Run("DeleteOrganization", func(t *testing.T) {
		tdb.truncateTables(t)
		user := tdb.createTestUser(t, "user-1", "user@example.com", "User")

		created, _ := ops.CreateOrganization(ctx, "Test Org", "test-org", user.ID, nil)

		err := ops.DeleteOrganization(ctx, created.ID)
		if err != nil {
			t.Fatalf("DeleteOrganization failed: %v", err)
		}

		_, err = ops.GetOrganization(ctx, created.ID)
		if err == nil {
			t.Error("Organization should be deleted")
		}
	})

	t.Run("ListUserOrganizations", func(t *testing.T) {
		tdb.truncateTables(t)
		user := tdb.createTestUser(t, "user-1", "user@example.com", "User")

		_, _ = ops.CreateOrganization(ctx, "Org 1", "org-1", user.ID, nil)
		_, _ = ops.CreateOrganization(ctx, "Org 2", "org-2", user.ID, nil)

		orgs, err := ops.ListUserOrganizations(ctx, user.ID)
		if err != nil {
			t.Fatalf("ListUserOrganizations failed: %v", err)
		}

		if len(orgs) != 2 {
			t.Errorf("len(orgs) = %d, want %d", len(orgs), 2)
		}
	})
}

func TestOrganizationOperations_Members(t *testing.T) {
	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	var ops organization.OrganizationOperations = createTestService(t, tdb.DB)

	t.Run("AddMember", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")
		member := tdb.createTestUser(t, "member-1", "member@example.com", "Member")

		org, _ := ops.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)

		added, err := ops.AddMember(ctx, org.ID, member.ID, "member")
		if err != nil {
			t.Fatalf("AddMember failed: %v", err)
		}

		if added.Role != "member" {
			t.Errorf("Role = %q, want %q", added.Role, "member")
		}
	})

	t.Run("RemoveMember", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")
		member := tdb.createTestUser(t, "member-1", "member@example.com", "Member")

		org, _ := ops.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)
		_, _ = ops.AddMember(ctx, org.ID, member.ID, "member")

		err := ops.RemoveMember(ctx, org.ID, member.ID)
		if err != nil {
			t.Fatalf("RemoveMember failed: %v", err)
		}

		_, err = ops.GetMember(ctx, org.ID, member.ID)
		if err == nil {
			t.Error("Member should be removed")
		}
	})

	t.Run("UpdateMemberRole", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")
		member := tdb.createTestUser(t, "member-1", "member@example.com", "Member")

		org, _ := ops.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)
		_, _ = ops.AddMember(ctx, org.ID, member.ID, "member")

		updated, err := ops.UpdateMemberRole(ctx, org.ID, member.ID, "admin")
		if err != nil {
			t.Fatalf("UpdateMemberRole failed: %v", err)
		}

		if updated.Role != "admin" {
			t.Errorf("Role = %q, want %q", updated.Role, "admin")
		}
	})

	t.Run("GetMember", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")
		member := tdb.createTestUser(t, "member-1", "member@example.com", "Member")

		org, _ := ops.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)
		_, _ = ops.AddMember(ctx, org.ID, member.ID, "admin")

		m, err := ops.GetMember(ctx, org.ID, member.ID)
		if err != nil {
			t.Fatalf("GetMember failed: %v", err)
		}

		if m.Role != "admin" {
			t.Errorf("Role = %q, want %q", m.Role, "admin")
		}
	})

	t.Run("ListMembers", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")
		member1 := tdb.createTestUser(t, "member-1", "member1@example.com", "Member 1")
		member2 := tdb.createTestUser(t, "member-2", "member2@example.com", "Member 2")

		org, _ := ops.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)
		_, _ = ops.AddMember(ctx, org.ID, member1.ID, "member")
		_, _ = ops.AddMember(ctx, org.ID, member2.ID, "member")

		members, err := ops.ListMembers(ctx, org.ID)
		if err != nil {
			t.Fatalf("ListMembers failed: %v", err)
		}

		if len(members) != 3 { // owner + 2 members
			t.Errorf("len(members) = %d, want %d", len(members), 3)
		}
	})

	t.Run("GetActiveMember", func(t *testing.T) {
		tdb.truncateTables(t)
		user := tdb.createTestUser(t, "user-1", "user@example.com", "User")

		_, _ = ops.CreateOrganization(ctx, "Test Org", "test-org", user.ID, nil)

		member, err := ops.GetActiveMember(ctx, user.ID)
		if err != nil {
			t.Fatalf("GetActiveMember failed: %v", err)
		}

		if member.UserID != user.ID {
			t.Errorf("UserID = %q, want %q", member.UserID, user.ID)
		}
	})
}

func TestOrganizationOperations_Invitations(t *testing.T) {
	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	var ops organization.OrganizationOperations = createTestService(t, tdb.DB)

	t.Run("CreateInvitation", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")

		org, _ := ops.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)

		inv, err := ops.CreateInvitation(ctx, org.ID, "invitee@example.com", "member", owner.ID)
		if err != nil {
			t.Fatalf("CreateInvitation failed: %v", err)
		}

		if inv.Status != "pending" {
			t.Errorf("Status = %q, want %q", inv.Status, "pending")
		}
	})

	t.Run("AcceptInvitation", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")
		invitee := tdb.createTestUser(t, "invitee-1", "invitee@example.com", "Invitee")

		org, _ := ops.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)
		inv, _ := ops.CreateInvitation(ctx, org.ID, invitee.Email, "member", owner.ID)

		member, err := ops.AcceptInvitation(ctx, inv.ID, invitee.ID)
		if err != nil {
			t.Fatalf("AcceptInvitation failed: %v", err)
		}

		if member.Role != "member" {
			t.Errorf("Role = %q, want %q", member.Role, "member")
		}
	})

	t.Run("RejectInvitation", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")
		invitee := tdb.createTestUser(t, "invitee-1", "invitee@example.com", "Invitee")

		org, _ := ops.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)
		inv, _ := ops.CreateInvitation(ctx, org.ID, invitee.Email, "member", owner.ID)

		err := ops.RejectInvitation(ctx, inv.ID, invitee.ID)
		if err != nil {
			t.Fatalf("RejectInvitation failed: %v", err)
		}

		updated, _ := ops.GetInvitation(ctx, inv.ID)
		if updated.Status != "rejected" {
			t.Errorf("Status = %q, want %q", updated.Status, "rejected")
		}
	})

	t.Run("CancelInvitation", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")

		org, _ := ops.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)
		inv, _ := ops.CreateInvitation(ctx, org.ID, "invitee@example.com", "member", owner.ID)

		err := ops.CancelInvitation(ctx, inv.ID, owner.ID)
		if err != nil {
			t.Fatalf("CancelInvitation failed: %v", err)
		}

		updated, _ := ops.GetInvitation(ctx, inv.ID)
		if updated.Status != "cancelled" {
			t.Errorf("Status = %q, want %q", updated.Status, "cancelled")
		}
	})

	t.Run("ListInvitations", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")

		org, _ := ops.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)
		_, _ = ops.CreateInvitation(ctx, org.ID, "inv1@example.com", "member", owner.ID)
		_, _ = ops.CreateInvitation(ctx, org.ID, "inv2@example.com", "admin", owner.ID)

		invitations, err := ops.ListInvitations(ctx, org.ID)
		if err != nil {
			t.Fatalf("ListInvitations failed: %v", err)
		}

		if len(invitations) != 2 {
			t.Errorf("len(invitations) = %d, want %d", len(invitations), 2)
		}
	})

	t.Run("ListUserInvitations", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")

		org1, _ := ops.CreateOrganization(ctx, "Org 1", "org-1", owner.ID, nil)
		org2, _ := ops.CreateOrganization(ctx, "Org 2", "org-2", owner.ID, nil)

		_, _ = ops.CreateInvitation(ctx, org1.ID, "invitee@example.com", "member", owner.ID)
		_, _ = ops.CreateInvitation(ctx, org2.ID, "invitee@example.com", "admin", owner.ID)

		invitations, err := ops.ListUserInvitations(ctx, "invitee@example.com")
		if err != nil {
			t.Fatalf("ListUserInvitations failed: %v", err)
		}

		if len(invitations) != 2 {
			t.Errorf("len(invitations) = %d, want %d", len(invitations), 2)
		}
	})

	t.Run("GetInvitation", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")

		org, _ := ops.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)
		created, _ := ops.CreateInvitation(ctx, org.ID, "invitee@example.com", "member", owner.ID)

		inv, err := ops.GetInvitation(ctx, created.ID)
		if err != nil {
			t.Fatalf("GetInvitation failed: %v", err)
		}

		if inv.ID != created.ID {
			t.Errorf("ID = %q, want %q", inv.ID, created.ID)
		}
	})
}

func TestOrganizationOperations_Teams(t *testing.T) {
	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	var ops organization.OrganizationOperations = createTestService(t, tdb.DB, organization.WithTeams(organization.TeamsConfig{Enabled: true}))

	t.Run("CreateTeam", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")

		org, _ := ops.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)

		team, err := ops.CreateTeam(ctx, org.ID, "Engineering")
		if err != nil {
			t.Fatalf("CreateTeam failed: %v", err)
		}

		if team.Name != "Engineering" {
			t.Errorf("Name = %q, want %q", team.Name, "Engineering")
		}
	})

	t.Run("GetTeam", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")

		org, _ := ops.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)
		created, _ := ops.CreateTeam(ctx, org.ID, "Engineering")

		team, err := ops.GetTeam(ctx, created.ID)
		if err != nil {
			t.Fatalf("GetTeam failed: %v", err)
		}

		if team.ID != created.ID {
			t.Errorf("ID = %q, want %q", team.ID, created.ID)
		}
	})

	t.Run("UpdateTeam", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")

		org, _ := ops.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)
		created, _ := ops.CreateTeam(ctx, org.ID, "Old Name")

		updated, err := ops.UpdateTeam(ctx, created.ID, "New Name")
		if err != nil {
			t.Fatalf("UpdateTeam failed: %v", err)
		}

		if updated.Name != "New Name" {
			t.Errorf("Name = %q, want %q", updated.Name, "New Name")
		}
	})

	t.Run("DeleteTeam", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")

		org, _ := ops.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)
		team, _ := ops.CreateTeam(ctx, org.ID, "Engineering")

		err := ops.DeleteTeam(ctx, team.ID)
		if err != nil {
			t.Fatalf("DeleteTeam failed: %v", err)
		}

		_, err = ops.GetTeam(ctx, team.ID)
		if err == nil {
			t.Error("Team should be deleted")
		}
	})

	t.Run("ListTeams", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")

		org, _ := ops.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)
		_, _ = ops.CreateTeam(ctx, org.ID, "Engineering")
		_, _ = ops.CreateTeam(ctx, org.ID, "Marketing")

		teams, err := ops.ListTeams(ctx, org.ID)
		if err != nil {
			t.Fatalf("ListTeams failed: %v", err)
		}

		if len(teams) != 2 {
			t.Errorf("len(teams) = %d, want %d", len(teams), 2)
		}
	})

	t.Run("AddTeamMember", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")
		member := tdb.createTestUser(t, "member-1", "member@example.com", "Member")

		org, _ := ops.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)
		_, _ = ops.AddMember(ctx, org.ID, member.ID, "member")
		team, _ := ops.CreateTeam(ctx, org.ID, "Engineering")

		tm, err := ops.AddTeamMember(ctx, team.ID, member.ID)
		if err != nil {
			t.Fatalf("AddTeamMember failed: %v", err)
		}

		if tm.UserID != member.ID {
			t.Errorf("UserID = %q, want %q", tm.UserID, member.ID)
		}
	})

	t.Run("RemoveTeamMember", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")
		member := tdb.createTestUser(t, "member-1", "member@example.com", "Member")

		org, _ := ops.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)
		_, _ = ops.AddMember(ctx, org.ID, member.ID, "member")
		team, _ := ops.CreateTeam(ctx, org.ID, "Engineering")
		_, _ = ops.AddTeamMember(ctx, team.ID, member.ID)

		err := ops.RemoveTeamMember(ctx, team.ID, member.ID)
		if err != nil {
			t.Fatalf("RemoveTeamMember failed: %v", err)
		}

		members, _ := ops.ListTeamMembers(ctx, team.ID)
		if len(members) != 0 {
			t.Error("Team member should be removed")
		}
	})

	t.Run("ListTeamMembers", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")
		member1 := tdb.createTestUser(t, "member-1", "member1@example.com", "Member 1")
		member2 := tdb.createTestUser(t, "member-2", "member2@example.com", "Member 2")

		org, _ := ops.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)
		_, _ = ops.AddMember(ctx, org.ID, member1.ID, "member")
		_, _ = ops.AddMember(ctx, org.ID, member2.ID, "member")
		team, _ := ops.CreateTeam(ctx, org.ID, "Engineering")
		_, _ = ops.AddTeamMember(ctx, team.ID, member1.ID)
		_, _ = ops.AddTeamMember(ctx, team.ID, member2.ID)

		members, err := ops.ListTeamMembers(ctx, team.ID)
		if err != nil {
			t.Fatalf("ListTeamMembers failed: %v", err)
		}

		if len(members) != 2 {
			t.Errorf("len(members) = %d, want %d", len(members), 2)
		}
	})
}

func TestOrganizationOperations_SessionManagement(t *testing.T) {
	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	var ops organization.OrganizationOperations = createTestService(t, tdb.DB)

	t.Run("SetActiveOrganization", func(t *testing.T) {
		tdb.truncateTables(t)
		user := tdb.createTestUser(t, "user-1", "user@example.com", "User")
		tdb.createTestSession(t, "session-1", user.ID)

		org, _ := ops.CreateOrganization(ctx, "Test Org", "test-org", user.ID, nil)

		err := ops.SetActiveOrganization(ctx, "session-1", &org.ID)
		if err != nil {
			t.Fatalf("SetActiveOrganization failed: %v", err)
		}
	})

	t.Run("GetActiveOrganization", func(t *testing.T) {
		tdb.truncateTables(t)
		user := tdb.createTestUser(t, "user-1", "user@example.com", "User")
		tdb.createTestSession(t, "session-1", user.ID)

		org, _ := ops.CreateOrganization(ctx, "Test Org", "test-org", user.ID, nil)
		_ = ops.SetActiveOrganization(ctx, "session-1", &org.ID)

		activeOrgID, err := ops.GetActiveOrganization(ctx, "session-1")
		if err != nil {
			t.Fatalf("GetActiveOrganization failed: %v", err)
		}

		if activeOrgID == nil || *activeOrgID != org.ID {
			t.Errorf("ActiveOrgID = %v, want %q", activeOrgID, org.ID)
		}
	})

	t.Run("SetActiveTeam", func(t *testing.T) {
		tdb.truncateTables(t)
		teamsOps := createTestService(t, tdb.DB, organization.WithTeams(organization.TeamsConfig{Enabled: true}))
		user := tdb.createTestUser(t, "user-1", "user@example.com", "User")
		tdb.createTestSession(t, "session-1", user.ID)

		org, _ := teamsOps.CreateOrganization(ctx, "Test Org", "test-org", user.ID, nil)
		team, _ := teamsOps.CreateTeam(ctx, org.ID, "Engineering")

		err := teamsOps.SetActiveTeam(ctx, "session-1", &team.ID)
		if err != nil {
			t.Fatalf("SetActiveTeam failed: %v", err)
		}
	})
}
