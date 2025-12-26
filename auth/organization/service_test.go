package organization_test

import (
	"context"
	"testing"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/organization"
)

func TestService_CreateOrganization(t *testing.T) {
	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	service := createTestService(t, tdb.DB)

	t.Run("creates organization successfully", func(t *testing.T) {
		tdb.truncateTables(t)
		user := tdb.createTestUser(t, "user-1", "test@example.com", "Test User")

		org, err := service.CreateOrganization(ctx, "Test Org", "test-org", user.ID, nil)
		if err != nil {
			t.Fatalf("CreateOrganization failed: %v", err)
		}

		if org.ID == "" {
			t.Error("Organization ID should not be empty")
		}

		if org.Name != "Test Org" {
			t.Errorf("Name = %q, want %q", org.Name, "Test Org")
		}

		if org.Slug != "test-org" {
			t.Errorf("Slug = %q, want %q", org.Slug, "test-org")
		}

		// Verify creator is added as owner
		member, err := service.GetMember(ctx, org.ID, user.ID)
		if err != nil {
			t.Fatalf("GetMember failed: %v", err)
		}

		if member.Role != "owner" {
			t.Errorf("Creator role = %q, want %q", member.Role, "owner")
		}
	})

	t.Run("creates organization with metadata", func(t *testing.T) {
		tdb.truncateTables(t)
		user := tdb.createTestUser(t, "user-1", "test@example.com", "Test User")

		metadata := map[string]any{
			"industry": "technology",
			"size":     "small",
		}

		org, err := service.CreateOrganization(ctx, "Org With Metadata", "org-with-meta", user.ID, metadata)
		if err != nil {
			t.Fatalf("CreateOrganization failed: %v", err)
		}

		if org.Metadata == nil {
			t.Error("Metadata should not be nil")
		}
	})

	t.Run("fails with duplicate slug", func(t *testing.T) {
		tdb.truncateTables(t)
		user := tdb.createTestUser(t, "user-1", "test@example.com", "Test User")

		_, err := service.CreateOrganization(ctx, "First Org", "same-slug", user.ID, nil)
		if err != nil {
			t.Fatalf("First CreateOrganization failed: %v", err)
		}

		_, err = service.CreateOrganization(ctx, "Second Org", "same-slug", user.ID, nil)
		if err == nil {
			t.Error("Should fail with duplicate slug")
		}
	})

	t.Run("respects organization limit", func(t *testing.T) {
		tdb.truncateTables(t)
		user := tdb.createTestUser(t, "user-1", "test@example.com", "Test User")

		// Create service with limit of 1
		limitService := createTestService(t, tdb.DB, organization.WithOrganizationLimit(func(userID string) int { return 1 }))

		_, err := limitService.CreateOrganization(ctx, "First Org", "first-org", user.ID, nil)
		if err != nil {
			t.Fatalf("First CreateOrganization failed: %v", err)
		}

		_, err = limitService.CreateOrganization(ctx, "Second Org", "second-org", user.ID, nil)
		if err == nil {
			t.Error("Should fail when organization limit exceeded")
		}
	})

	t.Run("respects AllowUserToCreateOrganization", func(t *testing.T) {
		tdb.truncateTables(t)
		user := tdb.createTestUser(t, "user-1", "test@example.com", "Test User")

		// Create service that doesn't allow org creation
		restrictedService := createTestService(t, tdb.DB, organization.WithAllowUserToCreateOrganization(func(userID string) bool { return false }))

		_, err := restrictedService.CreateOrganization(ctx, "Org", "org", user.ID, nil)
		if err == nil {
			t.Error("Should fail when user not allowed to create organizations")
		}
	})
}

func TestService_GetOrganization(t *testing.T) {
	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	service := createTestService(t, tdb.DB)

	t.Run("gets organization by ID", func(t *testing.T) {
		tdb.truncateTables(t)
		user := tdb.createTestUser(t, "user-1", "test@example.com", "Test User")

		created, _ := service.CreateOrganization(ctx, "Test Org", "test-org", user.ID, nil)

		org, err := service.GetOrganization(ctx, created.ID)
		if err != nil {
			t.Fatalf("GetOrganization failed: %v", err)
		}

		if org.ID != created.ID {
			t.Errorf("ID = %q, want %q", org.ID, created.ID)
		}
	})

	t.Run("fails for non-existent organization", func(t *testing.T) {
		tdb.truncateTables(t)

		_, err := service.GetOrganization(ctx, "non-existent-id")
		if err == nil {
			t.Error("Should fail for non-existent organization")
		}
	})
}

func TestService_GetOrganizationBySlug(t *testing.T) {
	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	service := createTestService(t, tdb.DB)

	t.Run("gets organization by slug", func(t *testing.T) {
		tdb.truncateTables(t)
		user := tdb.createTestUser(t, "user-1", "test@example.com", "Test User")

		created, _ := service.CreateOrganization(ctx, "Test Org", "my-test-org", user.ID, nil)

		org, err := service.GetOrganizationBySlug(ctx, "my-test-org")
		if err != nil {
			t.Fatalf("GetOrganizationBySlug failed: %v", err)
		}

		if org.ID != created.ID {
			t.Errorf("ID = %q, want %q", org.ID, created.ID)
		}
	})

	t.Run("fails for non-existent slug", func(t *testing.T) {
		tdb.truncateTables(t)

		_, err := service.GetOrganizationBySlug(ctx, "non-existent-slug")
		if err == nil {
			t.Error("Should fail for non-existent slug")
		}
	})
}

func TestService_UpdateOrganization(t *testing.T) {
	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	service := createTestService(t, tdb.DB)

	t.Run("updates organization name", func(t *testing.T) {
		tdb.truncateTables(t)
		user := tdb.createTestUser(t, "user-1", "test@example.com", "Test User")

		created, _ := service.CreateOrganization(ctx, "Old Name", "org-slug", user.ID, nil)

		updated, err := service.UpdateOrganization(ctx, created.ID, map[string]any{
			"name": "New Name",
		})
		if err != nil {
			t.Fatalf("UpdateOrganization failed: %v", err)
		}

		if updated.Name != "New Name" {
			t.Errorf("Name = %q, want %q", updated.Name, "New Name")
		}
	})

	t.Run("updates organization slug", func(t *testing.T) {
		tdb.truncateTables(t)
		user := tdb.createTestUser(t, "user-1", "test@example.com", "Test User")

		created, _ := service.CreateOrganization(ctx, "Test Org", "old-slug", user.ID, nil)

		updated, err := service.UpdateOrganization(ctx, created.ID, map[string]any{
			"slug": "new-slug",
		})
		if err != nil {
			t.Fatalf("UpdateOrganization failed: %v", err)
		}

		if updated.Slug != "new-slug" {
			t.Errorf("Slug = %q, want %q", updated.Slug, "new-slug")
		}
	})

	t.Run("fails with duplicate slug", func(t *testing.T) {
		tdb.truncateTables(t)
		user := tdb.createTestUser(t, "user-1", "test@example.com", "Test User")

		_, _ = service.CreateOrganization(ctx, "First Org", "first-slug", user.ID, nil)
		second, _ := service.CreateOrganization(ctx, "Second Org", "second-slug", user.ID, nil)

		_, err := service.UpdateOrganization(ctx, second.ID, map[string]any{
			"slug": "first-slug",
		})
		if err == nil {
			t.Error("Should fail with duplicate slug")
		}
	})
}

func TestService_DeleteOrganization(t *testing.T) {
	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	service := createTestService(t, tdb.DB)

	t.Run("deletes organization and related data", func(t *testing.T) {
		tdb.truncateTables(t)
		user := tdb.createTestUser(t, "user-1", "test@example.com", "Test User")

		org, _ := service.CreateOrganization(ctx, "Test Org", "test-org", user.ID, nil)

		err := service.DeleteOrganization(ctx, org.ID)
		if err != nil {
			t.Fatalf("DeleteOrganization failed: %v", err)
		}

		// Verify organization is deleted
		_, err = service.GetOrganization(ctx, org.ID)
		if err == nil {
			t.Error("Organization should be deleted")
		}

		// Verify members are deleted
		members, err := service.ListMembers(ctx, org.ID)
		if err != nil {
			t.Fatalf("ListMembers failed: %v", err)
		}
		if len(members) != 0 {
			t.Error("Members should be deleted")
		}
	})
}

func TestService_ListUserOrganizations(t *testing.T) {
	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	service := createTestService(t, tdb.DB)

	t.Run("lists user's organizations", func(t *testing.T) {
		tdb.truncateTables(t)
		user := tdb.createTestUser(t, "user-1", "test@example.com", "Test User")

		_, _ = service.CreateOrganization(ctx, "Org 1", "org-1", user.ID, nil)
		_, _ = service.CreateOrganization(ctx, "Org 2", "org-2", user.ID, nil)

		orgs, err := service.ListUserOrganizations(ctx, user.ID)
		if err != nil {
			t.Fatalf("ListUserOrganizations failed: %v", err)
		}

		if len(orgs) != 2 {
			t.Errorf("len(orgs) = %d, want %d", len(orgs), 2)
		}
	})

	t.Run("returns empty for user with no organizations", func(t *testing.T) {
		tdb.truncateTables(t)
		user2 := tdb.createTestUser(t, "user-2", "test2@example.com", "Test User 2")

		orgs, err := service.ListUserOrganizations(ctx, user2.ID)
		if err != nil {
			t.Fatalf("ListUserOrganizations failed: %v", err)
		}

		if len(orgs) != 0 {
			t.Errorf("len(orgs) = %d, want %d", len(orgs), 0)
		}
	})
}

func TestService_Members(t *testing.T) {
	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	service := createTestService(t, tdb.DB)

	t.Run("adds member to organization", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")
		member := tdb.createTestUser(t, "member-1", "member@example.com", "Member")

		org, _ := service.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)

		added, err := service.AddMember(ctx, org.ID, member.ID, "member")
		if err != nil {
			t.Fatalf("AddMember failed: %v", err)
		}

		if added.UserID != member.ID {
			t.Errorf("UserID = %q, want %q", added.UserID, member.ID)
		}

		if added.Role != "member" {
			t.Errorf("Role = %q, want %q", added.Role, "member")
		}
	})

	t.Run("removes member from organization", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")
		member := tdb.createTestUser(t, "member-1", "member@example.com", "Member")

		org, _ := service.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)
		_, _ = service.AddMember(ctx, org.ID, member.ID, "member")

		err := service.RemoveMember(ctx, org.ID, member.ID)
		if err != nil {
			t.Fatalf("RemoveMember failed: %v", err)
		}

		_, err = service.GetMember(ctx, org.ID, member.ID)
		if err == nil {
			t.Error("Member should be removed")
		}
	})

	t.Run("updates member role", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")
		member := tdb.createTestUser(t, "member-1", "member@example.com", "Member")

		org, _ := service.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)
		_, _ = service.AddMember(ctx, org.ID, member.ID, "member")

		updated, err := service.UpdateMemberRole(ctx, org.ID, member.ID, "admin")
		if err != nil {
			t.Fatalf("UpdateMemberRole failed: %v", err)
		}

		if updated.Role != "admin" {
			t.Errorf("Role = %q, want %q", updated.Role, "admin")
		}
	})

	t.Run("lists organization members", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")
		member1 := tdb.createTestUser(t, "member-1", "member1@example.com", "Member 1")
		member2 := tdb.createTestUser(t, "member-2", "member2@example.com", "Member 2")

		org, _ := service.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)
		_, _ = service.AddMember(ctx, org.ID, member1.ID, "member")
		_, _ = service.AddMember(ctx, org.ID, member2.ID, "admin")

		members, err := service.ListMembers(ctx, org.ID)
		if err != nil {
			t.Fatalf("ListMembers failed: %v", err)
		}

		// Should have 3 members: owner + 2 added
		if len(members) != 3 {
			t.Errorf("len(members) = %d, want %d", len(members), 3)
		}
	})
}

func TestService_Invitations(t *testing.T) {
	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	service := createTestService(t, tdb.DB)

	t.Run("creates invitation", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")

		org, _ := service.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)

		invitation, err := service.CreateInvitation(ctx, org.ID, "invitee@example.com", "member", owner.ID)
		if err != nil {
			t.Fatalf("CreateInvitation failed: %v", err)
		}

		if invitation.Email != "invitee@example.com" {
			t.Errorf("Email = %q, want %q", invitation.Email, "invitee@example.com")
		}

		if invitation.Status != "pending" {
			t.Errorf("Status = %q, want %q", invitation.Status, "pending")
		}

		if invitation.ExpiresAt == nil {
			t.Error("ExpiresAt should be set")
		}
	})

	t.Run("accepts invitation", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")
		invitee := tdb.createTestUser(t, "invitee-1", "invitee@example.com", "Invitee")

		org, _ := service.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)
		invitation, _ := service.CreateInvitation(ctx, org.ID, invitee.Email, "member", owner.ID)

		member, err := service.AcceptInvitation(ctx, invitation.ID, invitee.ID)
		if err != nil {
			t.Fatalf("AcceptInvitation failed: %v", err)
		}

		if member.UserID != invitee.ID {
			t.Errorf("UserID = %q, want %q", member.UserID, invitee.ID)
		}

		if member.Role != "member" {
			t.Errorf("Role = %q, want %q", member.Role, "member")
		}

		// Verify invitation status is updated
		updatedInv, _ := service.GetInvitation(ctx, invitation.ID)
		if updatedInv.Status != "accepted" {
			t.Errorf("Status = %q, want %q", updatedInv.Status, "accepted")
		}
	})

	t.Run("rejects invitation", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")
		invitee := tdb.createTestUser(t, "invitee-1", "invitee@example.com", "Invitee")

		org, _ := service.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)
		invitation, _ := service.CreateInvitation(ctx, org.ID, invitee.Email, "member", owner.ID)

		err := service.RejectInvitation(ctx, invitation.ID, invitee.ID)
		if err != nil {
			t.Fatalf("RejectInvitation failed: %v", err)
		}

		updatedInv, _ := service.GetInvitation(ctx, invitation.ID)
		if updatedInv.Status != "rejected" {
			t.Errorf("Status = %q, want %q", updatedInv.Status, "rejected")
		}
	})

	t.Run("cancels invitation", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")

		org, _ := service.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)
		invitation, _ := service.CreateInvitation(ctx, org.ID, "invitee@example.com", "member", owner.ID)

		err := service.CancelInvitation(ctx, invitation.ID, owner.ID)
		if err != nil {
			t.Fatalf("CancelInvitation failed: %v", err)
		}

		updatedInv, _ := service.GetInvitation(ctx, invitation.ID)
		if updatedInv.Status != "cancelled" {
			t.Errorf("Status = %q, want %q", updatedInv.Status, "cancelled")
		}
	})

	t.Run("lists organization invitations", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")

		org, _ := service.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)
		_, _ = service.CreateInvitation(ctx, org.ID, "invitee1@example.com", "member", owner.ID)
		_, _ = service.CreateInvitation(ctx, org.ID, "invitee2@example.com", "admin", owner.ID)

		invitations, err := service.ListInvitations(ctx, org.ID)
		if err != nil {
			t.Fatalf("ListInvitations failed: %v", err)
		}

		if len(invitations) != 2 {
			t.Errorf("len(invitations) = %d, want %d", len(invitations), 2)
		}
	})

	t.Run("lists user invitations by email", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")

		org1, _ := service.CreateOrganization(ctx, "Org 1", "org-1", owner.ID, nil)
		org2, _ := service.CreateOrganization(ctx, "Org 2", "org-2", owner.ID, nil)

		_, _ = service.CreateInvitation(ctx, org1.ID, "invitee@example.com", "member", owner.ID)
		_, _ = service.CreateInvitation(ctx, org2.ID, "invitee@example.com", "admin", owner.ID)

		invitations, err := service.ListUserInvitations(ctx, "invitee@example.com")
		if err != nil {
			t.Fatalf("ListUserInvitations failed: %v", err)
		}

		if len(invitations) != 2 {
			t.Errorf("len(invitations) = %d, want %d", len(invitations), 2)
		}
	})
}

func TestService_Teams(t *testing.T) {
	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	service := createTestService(t, tdb.DB, organization.WithTeams(organization.TeamsConfig{Enabled: true}))

	t.Run("creates team", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")

		org, _ := service.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)

		team, err := service.CreateTeam(ctx, org.ID, "Engineering")
		if err != nil {
			t.Fatalf("CreateTeam failed: %v", err)
		}

		if team.Name != "Engineering" {
			t.Errorf("Name = %q, want %q", team.Name, "Engineering")
		}

		if team.OrganizationID != org.ID {
			t.Errorf("OrganizationID = %q, want %q", team.OrganizationID, org.ID)
		}
	})

	t.Run("fails when teams disabled", func(t *testing.T) {
		tdb.truncateTables(t)
		disabledService := createTestService(t, tdb.DB) // Teams disabled by default
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")

		org, _ := disabledService.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)

		_, err := disabledService.CreateTeam(ctx, org.ID, "Engineering")
		if err == nil {
			t.Error("Should fail when teams are disabled")
		}
	})

	t.Run("gets team by ID", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")

		org, _ := service.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)
		created, _ := service.CreateTeam(ctx, org.ID, "Engineering")

		team, err := service.GetTeam(ctx, created.ID)
		if err != nil {
			t.Fatalf("GetTeam failed: %v", err)
		}

		if team.ID != created.ID {
			t.Errorf("ID = %q, want %q", team.ID, created.ID)
		}
	})

	t.Run("updates team", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")

		org, _ := service.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)
		created, _ := service.CreateTeam(ctx, org.ID, "Old Name")

		updated, err := service.UpdateTeam(ctx, created.ID, "New Name")
		if err != nil {
			t.Fatalf("UpdateTeam failed: %v", err)
		}

		if updated.Name != "New Name" {
			t.Errorf("Name = %q, want %q", updated.Name, "New Name")
		}
	})

	t.Run("deletes team", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")

		org, _ := service.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)
		team, _ := service.CreateTeam(ctx, org.ID, "Engineering")

		err := service.DeleteTeam(ctx, team.ID)
		if err != nil {
			t.Fatalf("DeleteTeam failed: %v", err)
		}

		_, err = service.GetTeam(ctx, team.ID)
		if err == nil {
			t.Error("Team should be deleted")
		}
	})

	t.Run("lists organization teams", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")

		org, _ := service.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)
		_, _ = service.CreateTeam(ctx, org.ID, "Engineering")
		_, _ = service.CreateTeam(ctx, org.ID, "Marketing")

		teams, err := service.ListTeams(ctx, org.ID)
		if err != nil {
			t.Fatalf("ListTeams failed: %v", err)
		}

		if len(teams) != 2 {
			t.Errorf("len(teams) = %d, want %d", len(teams), 2)
		}
	})
}

func TestService_TeamMembers(t *testing.T) {
	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	service := createTestService(t, tdb.DB, organization.WithTeams(organization.TeamsConfig{Enabled: true}))

	t.Run("adds member to team", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")
		member := tdb.createTestUser(t, "member-1", "member@example.com", "Member")

		org, _ := service.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)
		_, _ = service.AddMember(ctx, org.ID, member.ID, "member")
		team, _ := service.CreateTeam(ctx, org.ID, "Engineering")

		teamMember, err := service.AddTeamMember(ctx, team.ID, member.ID)
		if err != nil {
			t.Fatalf("AddTeamMember failed: %v", err)
		}

		if teamMember.UserID != member.ID {
			t.Errorf("UserID = %q, want %q", teamMember.UserID, member.ID)
		}
	})

	t.Run("removes member from team", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")
		member := tdb.createTestUser(t, "member-1", "member@example.com", "Member")

		org, _ := service.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)
		_, _ = service.AddMember(ctx, org.ID, member.ID, "member")
		team, _ := service.CreateTeam(ctx, org.ID, "Engineering")
		_, _ = service.AddTeamMember(ctx, team.ID, member.ID)

		err := service.RemoveTeamMember(ctx, team.ID, member.ID)
		if err != nil {
			t.Fatalf("RemoveTeamMember failed: %v", err)
		}

		members, _ := service.ListTeamMembers(ctx, team.ID)
		if len(members) != 0 {
			t.Error("Team member should be removed")
		}
	})

	t.Run("lists team members", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")
		member1 := tdb.createTestUser(t, "member-1", "member1@example.com", "Member 1")
		member2 := tdb.createTestUser(t, "member-2", "member2@example.com", "Member 2")

		org, _ := service.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)
		_, _ = service.AddMember(ctx, org.ID, member1.ID, "member")
		_, _ = service.AddMember(ctx, org.ID, member2.ID, "member")
		team, _ := service.CreateTeam(ctx, org.ID, "Engineering")
		_, _ = service.AddTeamMember(ctx, team.ID, member1.ID)
		_, _ = service.AddTeamMember(ctx, team.ID, member2.ID)

		members, err := service.ListTeamMembers(ctx, team.ID)
		if err != nil {
			t.Fatalf("ListTeamMembers failed: %v", err)
		}

		if len(members) != 2 {
			t.Errorf("len(members) = %d, want %d", len(members), 2)
		}
	})
}

func TestService_SessionManagement(t *testing.T) {
	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	service := createTestService(t, tdb.DB)

	t.Run("sets active organization", func(t *testing.T) {
		tdb.truncateTables(t)
		user := tdb.createTestUser(t, "user-1", "user@example.com", "User")
		tdb.createTestSession(t, "session-1", user.ID)

		org, _ := service.CreateOrganization(ctx, "Test Org", "test-org", user.ID, nil)

		err := service.SetActiveOrganization(ctx, "session-1", &org.ID)
		if err != nil {
			t.Fatalf("SetActiveOrganization failed: %v", err)
		}

		activeOrgID, err := service.GetActiveOrganization(ctx, "session-1")
		if err != nil {
			t.Fatalf("GetActiveOrganization failed: %v", err)
		}

		if activeOrgID == nil || *activeOrgID != org.ID {
			t.Errorf("ActiveOrganizationID = %v, want %q", activeOrgID, org.ID)
		}
	})

	t.Run("clears active organization", func(t *testing.T) {
		tdb.truncateTables(t)
		user := tdb.createTestUser(t, "user-1", "user@example.com", "User")
		tdb.createTestSession(t, "session-1", user.ID)

		org, _ := service.CreateOrganization(ctx, "Test Org", "test-org", user.ID, nil)
		_ = service.SetActiveOrganization(ctx, "session-1", &org.ID)

		err := service.SetActiveOrganization(ctx, "session-1", nil)
		if err != nil {
			t.Fatalf("SetActiveOrganization (clear) failed: %v", err)
		}

		activeOrgID, err := service.GetActiveOrganization(ctx, "session-1")
		if err != nil {
			t.Fatalf("GetActiveOrganization failed: %v", err)
		}

		if activeOrgID != nil {
			t.Errorf("ActiveOrganizationID = %v, want nil", activeOrgID)
		}
	})

	t.Run("fails with invalid organization", func(t *testing.T) {
		tdb.truncateTables(t)
		user := tdb.createTestUser(t, "user-1", "user@example.com", "User")
		tdb.createTestSession(t, "session-1", user.ID)

		invalidID := "invalid-org-id"
		err := service.SetActiveOrganization(ctx, "session-1", &invalidID)
		if err == nil {
			t.Error("Should fail with invalid organization ID")
		}
	})
}

func TestService_Hooks(t *testing.T) {
	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()

	t.Run("calls organization hooks", func(t *testing.T) {
		tdb.truncateTables(t)
		user := tdb.createTestUser(t, "user-1", "user@example.com", "User")

		beforeCalled := false
		afterCalled := false

		service := createTestService(t, tdb.DB, organization.WithOrganizationHooks(organization.OrganizationHooks{
			BeforeCreateOrganization: func(org *organization.Organization, userID string) error {
				beforeCalled = true
				return nil
			},
			AfterCreateOrganization: func(org *organization.Organization, member *organization.Member, userID string) error {
				afterCalled = true
				return nil
			},
		}))

		_, err := service.CreateOrganization(ctx, "Test Org", "test-org", user.ID, nil)
		if err != nil {
			t.Fatalf("CreateOrganization failed: %v", err)
		}

		if !beforeCalled {
			t.Error("BeforeCreateOrganization hook was not called")
		}

		if !afterCalled {
			t.Error("AfterCreateOrganization hook was not called")
		}
	})

	t.Run("calls member hooks", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")
		member := tdb.createTestUser(t, "member-1", "member@example.com", "Member")

		beforeAddCalled := false
		afterAddCalled := false

		service := createTestService(t, tdb.DB, organization.WithOrganizationHooks(organization.OrganizationHooks{
			BeforeAddMember: func(m *organization.Member, userID string) error {
				beforeAddCalled = true
				return nil
			},
			AfterAddMember: func(m *organization.Member, userID string) error {
				afterAddCalled = true
				return nil
			},
		}))

		org, _ := service.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)
		_, _ = service.AddMember(ctx, org.ID, member.ID, "member")

		if !beforeAddCalled {
			t.Error("BeforeAddMember hook was not called")
		}

		if !afterAddCalled {
			t.Error("AfterAddMember hook was not called")
		}
	})

	t.Run("calls invitation hooks", func(t *testing.T) {
		tdb.truncateTables(t)
		owner := tdb.createTestUser(t, "owner-1", "owner@example.com", "Owner")

		beforeCalled := false
		afterCalled := false

		service := createTestService(t, tdb.DB, organization.WithOrganizationHooks(organization.OrganizationHooks{
			BeforeCreateInvitation: func(inv *organization.Invitation, inviterID string) error {
				beforeCalled = true
				return nil
			},
			AfterCreateInvitation: func(inv *organization.Invitation, inviterID string) error {
				afterCalled = true
				return nil
			},
		}))

		org, _ := service.CreateOrganization(ctx, "Test Org", "test-org", owner.ID, nil)
		_, _ = service.CreateInvitation(ctx, org.ID, "invitee@example.com", "member", owner.ID)

		if !beforeCalled {
			t.Error("BeforeCreateInvitation hook was not called")
		}

		if !afterCalled {
			t.Error("AfterCreateInvitation hook was not called")
		}
	})
}
