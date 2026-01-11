package organization

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	orgdb "github.com/webdeveloperben/BetterAuthGoServer/auth/organization/db"
	coredb "github.com/webdeveloperben/BetterAuthGoServer/db"
)

// Service provides organization operations using the store adapter.
type Service struct {
	store   *StoreAdapter
	rawDB   coredb.DBTX // Kept for queries not yet migrated (like session updates)
	dialect coredb.Dialect
	logger  *slog.Logger
	config  *Config
}

// NewService creates a new organization service.
func NewService(dbStore *orgdb.Store, rawDB coredb.DBTX, dialect coredb.Dialect, logger *slog.Logger, config *Config) *Service {
	return &Service{
		store:   NewStoreAdapter(dbStore),
		rawDB:   rawDB,
		dialect: dialect,
		logger:  logger,
		config:  config,
	}
}

// CreateOrganization creates a new organization.
func (s *Service) CreateOrganization(ctx context.Context, name, slug string, creatorID string, metadata map[string]any) (*Organization, error) {
	// Check if user can create organizations
	if !s.config.AllowUserToCreateOrganization(creatorID) {
		return nil, fmt.Errorf("user not allowed to create organizations")
	}

	// Check organization limit by counting user's owned organizations
	members, err := s.store.ListMembersByUser(ctx, creatorID)
	if err != nil {
		return nil, fmt.Errorf("failed to check organization count: %w", err)
	}
	var userOrgCount int
	for _, m := range members {
		if m.Role == "owner" {
			userOrgCount++
		}
	}

	if userOrgCount >= s.config.OrganizationLimit(creatorID) {
		return nil, fmt.Errorf("organization limit exceeded")
	}

	// Check if slug is unique
	slugExists, err := s.store.CheckSlugExists(ctx, slug)
	if err != nil {
		return nil, fmt.Errorf("failed to check slug uniqueness: %w", err)
	}
	if slugExists {
		return nil, fmt.Errorf("organization slug already exists")
	}

	now := time.Now()

	// Serialize metadata
	var metadataStr *string
	if metadata != nil {
		data, err := json.Marshal(metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal metadata: %w", err)
		}
		str := string(data)
		metadataStr = &str
	}

	org := &Organization{
		ID:        generateID(),
		Name:      name,
		Slug:      slug,
		Metadata:  metadataStr,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Run before hook
	if s.config.OrganizationHooks.BeforeCreateOrganization != nil {
		if err := s.config.OrganizationHooks.BeforeCreateOrganization(org, creatorID); err != nil {
			return nil, fmt.Errorf("before create organization hook failed: %w", err)
		}
	}

	// Create organization
	if err := s.store.CreateOrganization(ctx, org); err != nil {
		return nil, fmt.Errorf("failed to create organization: %w", err)
	}

	// Add creator as member with appropriate role
	member := &Member{
		ID:             generateID(),
		UserID:         creatorID,
		OrganizationID: org.ID,
		Role:           s.config.CreatorRole,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.store.CreateMember(ctx, member); err != nil {
		return nil, fmt.Errorf("failed to add creator as member: %w", err)
	}

	// Run after hook
	if s.config.OrganizationHooks.AfterCreateOrganization != nil {
		if err := s.config.OrganizationHooks.AfterCreateOrganization(org, member, creatorID); err != nil {
			s.logger.Error("after create organization hook failed", "error", err)
		}
	}

	return org, nil
}

// GetOrganization retrieves an organization by ID.
func (s *Service) GetOrganization(ctx context.Context, id string) (*Organization, error) {
	org, err := s.store.GetOrganizationByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}
	if org == nil {
		return nil, fmt.Errorf("organization not found")
	}
	return org, nil
}

// GetOrganizationBySlug retrieves an organization by slug.
func (s *Service) GetOrganizationBySlug(ctx context.Context, slug string) (*Organization, error) {
	org, err := s.store.GetOrganizationBySlug(ctx, slug)
	if err != nil {
		return nil, fmt.Errorf("failed to get organization by slug: %w", err)
	}
	if org == nil {
		return nil, fmt.Errorf("organization not found")
	}
	return org, nil
}

// UpdateOrganization updates an organization.
func (s *Service) UpdateOrganization(ctx context.Context, id string, updates map[string]any) (*Organization, error) {
	org, err := s.GetOrganization(ctx, id)
	if err != nil {
		return nil, err
	}

	// Run before hook
	if s.config.OrganizationHooks.BeforeUpdateOrganization != nil {
		if err := s.config.OrganizationHooks.BeforeUpdateOrganization(org, ""); err != nil {
			return nil, fmt.Errorf("before update organization hook failed: %w", err)
		}
	}

	// Apply updates
	if name, ok := updates["name"].(string); ok {
		org.Name = name
	}
	if slug, ok := updates["slug"].(string); ok {
		// Check slug uniqueness if changing
		if slug != org.Slug {
			existingOrg, err := s.store.GetOrganizationBySlug(ctx, slug)
			if err != nil {
				return nil, fmt.Errorf("failed to check slug uniqueness: %w", err)
			}
			if existingOrg != nil && existingOrg.ID != id {
				return nil, fmt.Errorf("organization slug already exists")
			}
		}
		org.Slug = slug
	}
	if logo, ok := updates["logo"].(*string); ok {
		org.Logo = logo
	}
	if metadata, ok := updates["metadata"].(map[string]any); ok {
		data, err := json.Marshal(metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal metadata: %w", err)
		}
		str := string(data)
		org.Metadata = &str
	}

	org.UpdatedAt = time.Now()

	if err := s.store.UpdateOrganization(ctx, org); err != nil {
		return nil, fmt.Errorf("failed to update organization: %w", err)
	}

	// Run after hook
	if s.config.OrganizationHooks.AfterUpdateOrganization != nil {
		if err := s.config.OrganizationHooks.AfterUpdateOrganization(org, ""); err != nil {
			s.logger.Error("after update organization hook failed", "error", err)
		}
	}

	return org, nil
}

// DeleteOrganization deletes an organization and all related data.
func (s *Service) DeleteOrganization(ctx context.Context, id string) error {
	// Run before hook
	if s.config.OrganizationHooks.BeforeDeleteOrganization != nil {
		org, _ := s.GetOrganization(ctx, id)
		if err := s.config.OrganizationHooks.BeforeDeleteOrganization(org, ""); err != nil {
			return fmt.Errorf("before delete organization hook failed: %w", err)
		}
	}

	// Delete team members for teams in this org
	teams, err := s.store.ListTeamsByOrganization(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to list teams: %w", err)
	}
	for _, team := range teams {
		members, err := s.store.ListTeamMembersByTeam(ctx, team.ID)
		if err != nil {
			return fmt.Errorf("failed to list team members: %w", err)
		}
		for _, m := range members {
			if err := s.store.DeleteTeamMember(ctx, team.ID, m.UserID); err != nil {
				return fmt.Errorf("failed to delete team member: %w", err)
			}
		}
		if err := s.store.DeleteTeam(ctx, team.ID); err != nil {
			return fmt.Errorf("failed to delete team: %w", err)
		}
	}

	// Delete invitations - use CancelPendingInvitations for all emails (or iterate)
	invitations, err := s.store.ListInvitationsByOrganization(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to list invitations: %w", err)
	}
	for _, inv := range invitations {
		if err := s.store.UpdateInvitationStatus(ctx, inv.ID, "cancelled"); err != nil {
			s.logger.Warn("failed to cancel invitation", "id", inv.ID, "error", err)
		}
	}

	// Delete members
	members, err := s.store.ListMembersByOrganization(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to list members: %w", err)
	}
	for _, m := range members {
		if err := s.store.DeleteMember(ctx, id, m.UserID); err != nil {
			return fmt.Errorf("failed to delete member: %w", err)
		}
	}

	// Delete organization
	if err := s.store.DeleteOrganization(ctx, id); err != nil {
		return fmt.Errorf("failed to delete organization: %w", err)
	}

	// Run after hook
	if s.config.OrganizationHooks.AfterDeleteOrganization != nil {
		if err := s.config.OrganizationHooks.AfterDeleteOrganization(nil, ""); err != nil {
			s.logger.Error("after delete organization hook failed", "error", err)
		}
	}

	return nil
}

// ListUserOrganizations returns organizations where the user is a member.
func (s *Service) ListUserOrganizations(ctx context.Context, userID string) ([]*Organization, error) {
	orgs, err := s.store.ListUserOrganizations(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list user organizations: %w", err)
	}
	return orgs, nil
}

// AddMember adds a user to an organization.
func (s *Service) AddMember(ctx context.Context, organizationID, userID, role string) (*Member, error) {
	// Run before hook
	if s.config.OrganizationHooks.BeforeAddMember != nil {
		member := &Member{
			UserID:         userID,
			OrganizationID: organizationID,
			Role:           role,
		}
		if err := s.config.OrganizationHooks.BeforeAddMember(member, userID); err != nil {
			return nil, fmt.Errorf("before add member hook failed: %w", err)
		}
	}

	now := time.Now()
	member := &Member{
		ID:             generateID(),
		UserID:         userID,
		OrganizationID: organizationID,
		Role:           role,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := s.store.CreateMember(ctx, member); err != nil {
		return nil, fmt.Errorf("failed to add member: %w", err)
	}

	// Run after hook
	if s.config.OrganizationHooks.AfterAddMember != nil {
		if err := s.config.OrganizationHooks.AfterAddMember(member, userID); err != nil {
			s.logger.Error("after add member hook failed", "error", err)
		}
	}

	return member, nil
}

// RemoveMember removes a user from an organization.
func (s *Service) RemoveMember(ctx context.Context, organizationID, userID string) error {
	// Run before hook
	if s.config.OrganizationHooks.BeforeRemoveMember != nil {
		member, _ := s.GetMember(ctx, organizationID, userID)
		if err := s.config.OrganizationHooks.BeforeRemoveMember(member, userID); err != nil {
			return fmt.Errorf("before remove member hook failed: %w", err)
		}
	}

	if err := s.store.DeleteMember(ctx, organizationID, userID); err != nil {
		return fmt.Errorf("failed to remove member: %w", err)
	}

	// Run after hook
	if s.config.OrganizationHooks.AfterRemoveMember != nil {
		if err := s.config.OrganizationHooks.AfterRemoveMember(nil, userID); err != nil {
			s.logger.Error("after remove member hook failed", "error", err)
		}
	}

	return nil
}

// UpdateMemberRole updates a member's role.
func (s *Service) UpdateMemberRole(ctx context.Context, organizationID, userID, role string) (*Member, error) {
	member, err := s.GetMember(ctx, organizationID, userID)
	if err != nil {
		return nil, err
	}

	oldRole := member.Role

	// Run before hook
	if s.config.OrganizationHooks.BeforeUpdateMemberRole != nil {
		if err := s.config.OrganizationHooks.BeforeUpdateMemberRole(member, role, userID); err != nil {
			return nil, fmt.Errorf("before update member role hook failed: %w", err)
		}
	}

	now := time.Now()
	if err := s.store.UpdateMemberRole(ctx, member.ID, role, now); err != nil {
		return nil, fmt.Errorf("failed to update member role: %w", err)
	}

	member.Role = role
	member.UpdatedAt = now

	// Run after hook
	if s.config.OrganizationHooks.AfterUpdateMemberRole != nil {
		if err := s.config.OrganizationHooks.AfterUpdateMemberRole(member, oldRole, userID); err != nil {
			s.logger.Error("after update member role hook failed", "error", err)
		}
	}

	return member, nil
}

// GetMember retrieves a member.
func (s *Service) GetMember(ctx context.Context, organizationID, userID string) (*Member, error) {
	member, err := s.store.GetMember(ctx, organizationID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get member: %w", err)
	}
	if member == nil {
		return nil, fmt.Errorf("member not found")
	}
	return member, nil
}

// ListMembers lists all members of an organization.
func (s *Service) ListMembers(ctx context.Context, organizationID string) ([]*Member, error) {
	members, err := s.store.ListMembersByOrganization(ctx, organizationID)
	if err != nil {
		return nil, fmt.Errorf("failed to list members: %w", err)
	}
	return members, nil
}

// GetActiveMember gets the user's active member record.
func (s *Service) GetActiveMember(ctx context.Context, userID string) (*Member, error) {
	member, err := s.store.GetFirstMemberByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get active member: %w", err)
	}
	if member == nil {
		return nil, fmt.Errorf("no membership found")
	}
	return member, nil
}

// CreateInvitation creates an invitation to join an organization.
func (s *Service) CreateInvitation(ctx context.Context, organizationID, email, role, inviterID string) (*Invitation, error) {
	expiresAt := time.Now().Add(s.config.InvitationExpiresIn)

	invitation := &Invitation{
		ID:             generateID(),
		Email:          email,
		OrganizationID: organizationID,
		InviterID:      inviterID,
		Role:           role,
		Status:         "pending",
		ExpiresAt:      &expiresAt,
		CreatedAt:      time.Now(),
	}

	// Run before hook
	if s.config.OrganizationHooks.BeforeCreateInvitation != nil {
		if err := s.config.OrganizationHooks.BeforeCreateInvitation(invitation, inviterID); err != nil {
			return nil, fmt.Errorf("before create invitation hook failed: %w", err)
		}
	}

	if err := s.store.CreateInvitation(ctx, invitation); err != nil {
		return nil, fmt.Errorf("failed to create invitation: %w", err)
	}

	// Send email if configured
	if s.config.SendInvitationEmail != nil {
		org, _ := s.GetOrganization(ctx, organizationID)
		if err := s.config.SendInvitationEmail(invitation, org); err != nil {
			s.logger.Error("failed to send invitation email", "error", err)
		}
	}

	// Run after hook
	if s.config.OrganizationHooks.AfterCreateInvitation != nil {
		if err := s.config.OrganizationHooks.AfterCreateInvitation(invitation, inviterID); err != nil {
			s.logger.Error("after create invitation hook failed", "error", err)
		}
	}

	return invitation, nil
}

// AcceptInvitation accepts an invitation and adds the user as a member.
func (s *Service) AcceptInvitation(ctx context.Context, invitationID, userID string) (*Member, error) {
	invitation, err := s.GetInvitation(ctx, invitationID)
	if err != nil {
		return nil, err
	}

	if invitation.Status != "pending" {
		return nil, fmt.Errorf("invitation is not pending")
	}

	if invitation.ExpiresAt != nil && time.Now().After(*invitation.ExpiresAt) {
		return nil, fmt.Errorf("invitation has expired")
	}

	// Run before hook
	if s.config.OrganizationHooks.BeforeAcceptInvitation != nil {
		if err := s.config.OrganizationHooks.BeforeAcceptInvitation(invitation, userID); err != nil {
			return nil, fmt.Errorf("before accept invitation hook failed: %w", err)
		}
	}

	// Add member
	now := time.Now()
	member := &Member{
		ID:             generateID(),
		UserID:         userID,
		OrganizationID: invitation.OrganizationID,
		Role:           invitation.Role,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := s.store.CreateMember(ctx, member); err != nil {
		return nil, fmt.Errorf("failed to add member: %w", err)
	}

	// Update invitation status
	if err := s.store.UpdateInvitationStatus(ctx, invitationID, "accepted"); err != nil {
		return nil, fmt.Errorf("failed to update invitation status: %w", err)
	}

	// Run after hook
	if s.config.OrganizationHooks.AfterAcceptInvitation != nil {
		if err := s.config.OrganizationHooks.AfterAcceptInvitation(invitation, member, userID); err != nil {
			s.logger.Error("after accept invitation hook failed", "error", err)
		}
	}

	return member, nil
}

// RejectInvitation rejects an invitation.
func (s *Service) RejectInvitation(ctx context.Context, invitationID, userID string) error {
	invitation, err := s.GetInvitation(ctx, invitationID)
	if err != nil {
		return err
	}

	if invitation.Status != "pending" {
		return fmt.Errorf("invitation is not pending")
	}

	// Run before hook
	if s.config.OrganizationHooks.BeforeRejectInvitation != nil {
		if err := s.config.OrganizationHooks.BeforeRejectInvitation(invitation, userID); err != nil {
			return fmt.Errorf("before reject invitation hook failed: %w", err)
		}
	}

	if err := s.store.UpdateInvitationStatus(ctx, invitationID, "rejected"); err != nil {
		return fmt.Errorf("failed to reject invitation: %w", err)
	}

	// Run after hook
	if s.config.OrganizationHooks.AfterRejectInvitation != nil {
		if err := s.config.OrganizationHooks.AfterRejectInvitation(invitation, userID); err != nil {
			s.logger.Error("after reject invitation hook failed", "error", err)
		}
	}

	return nil
}

// CancelInvitation cancels an invitation.
func (s *Service) CancelInvitation(ctx context.Context, invitationID, cancelledBy string) error {
	invitation, err := s.GetInvitation(ctx, invitationID)
	if err != nil {
		return err
	}

	// Run before hook
	if s.config.OrganizationHooks.BeforeCancelInvitation != nil {
		if err := s.config.OrganizationHooks.BeforeCancelInvitation(invitation, cancelledBy); err != nil {
			return fmt.Errorf("before cancel invitation hook failed: %w", err)
		}
	}

	if err := s.store.UpdateInvitationStatus(ctx, invitationID, "cancelled"); err != nil {
		return fmt.Errorf("failed to cancel invitation: %w", err)
	}

	// Run after hook
	if s.config.OrganizationHooks.AfterCancelInvitation != nil {
		if err := s.config.OrganizationHooks.AfterCancelInvitation(invitation, cancelledBy); err != nil {
			s.logger.Error("after cancel invitation hook failed", "error", err)
		}
	}

	return nil
}

// ListInvitations lists invitations for an organization.
func (s *Service) ListInvitations(ctx context.Context, organizationID string) ([]*Invitation, error) {
	invitations, err := s.store.ListInvitationsByOrganization(ctx, organizationID)
	if err != nil {
		return nil, fmt.Errorf("failed to list invitations: %w", err)
	}
	return invitations, nil
}

// GetInvitation retrieves an invitation by ID.
func (s *Service) GetInvitation(ctx context.Context, id string) (*Invitation, error) {
	invitation, err := s.store.GetInvitationByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get invitation: %w", err)
	}
	if invitation == nil {
		return nil, fmt.Errorf("invitation not found")
	}
	return invitation, nil
}

// ListUserInvitations lists pending invitations for a user by email.
func (s *Service) ListUserInvitations(ctx context.Context, email string) ([]*Invitation, error) {
	invitations, err := s.store.ListPendingInvitationsByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("failed to list user invitations: %w", err)
	}
	return invitations, nil
}

// CreateTeam creates a new team (if teams are enabled).
func (s *Service) CreateTeam(ctx context.Context, organizationID, name string) (*Team, error) {
	if !s.config.Teams.Enabled {
		return nil, fmt.Errorf("teams are not enabled")
	}

	now := time.Now()
	team := &Team{
		ID:             generateID(),
		Name:           name,
		OrganizationID: organizationID,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := s.store.CreateTeam(ctx, team); err != nil {
		return nil, fmt.Errorf("failed to create team: %w", err)
	}

	return team, nil
}

// GetTeam retrieves a team by ID.
func (s *Service) GetTeam(ctx context.Context, teamID string) (*Team, error) {
	team, err := s.store.GetTeamByID(ctx, teamID)
	if err != nil {
		return nil, fmt.Errorf("failed to get team: %w", err)
	}
	if team == nil {
		return nil, fmt.Errorf("team not found")
	}
	return team, nil
}

// UpdateTeam updates a team.
func (s *Service) UpdateTeam(ctx context.Context, teamID, name string) (*Team, error) {
	team, err := s.GetTeam(ctx, teamID)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	if err := s.store.UpdateTeam(ctx, teamID, name, now); err != nil {
		return nil, fmt.Errorf("failed to update team: %w", err)
	}

	team.Name = name
	team.UpdatedAt = now
	return team, nil
}

// DeleteTeam deletes a team.
func (s *Service) DeleteTeam(ctx context.Context, teamID string) error {
	// First delete all team members
	members, err := s.store.ListTeamMembersByTeam(ctx, teamID)
	if err != nil {
		return fmt.Errorf("failed to list team members: %w", err)
	}
	for _, m := range members {
		if err := s.store.DeleteTeamMember(ctx, teamID, m.UserID); err != nil {
			return fmt.Errorf("failed to delete team member: %w", err)
		}
	}

	if err := s.store.DeleteTeam(ctx, teamID); err != nil {
		return fmt.Errorf("failed to delete team: %w", err)
	}
	return nil
}

// ListTeams lists teams for an organization.
func (s *Service) ListTeams(ctx context.Context, organizationID string) ([]*Team, error) {
	teams, err := s.store.ListTeamsByOrganization(ctx, organizationID)
	if err != nil {
		return nil, fmt.Errorf("failed to list teams: %w", err)
	}
	return teams, nil
}

// AddTeamMember adds a user to a team.
func (s *Service) AddTeamMember(ctx context.Context, teamID, userID string) (*TeamMember, error) {
	teamMember := &TeamMember{
		ID:        generateID(),
		TeamID:    teamID,
		UserID:    userID,
		CreatedAt: time.Now(),
	}

	if err := s.store.CreateTeamMember(ctx, teamMember); err != nil {
		return nil, fmt.Errorf("failed to add team member: %w", err)
	}

	return teamMember, nil
}

// RemoveTeamMember removes a user from a team.
func (s *Service) RemoveTeamMember(ctx context.Context, teamID, userID string) error {
	if err := s.store.DeleteTeamMember(ctx, teamID, userID); err != nil {
		return fmt.Errorf("failed to remove team member: %w", err)
	}
	return nil
}

// ListTeamMembers lists members of a team.
func (s *Service) ListTeamMembers(ctx context.Context, teamID string) ([]*TeamMember, error) {
	members, err := s.store.ListTeamMembersByTeam(ctx, teamID)
	if err != nil {
		return nil, fmt.Errorf("failed to list team members: %w", err)
	}
	return members, nil
}

// SetActiveOrganization sets the active organization for a session.
// Note: This still uses raw SQL as session table extensions are not yet in sqlc.
func (s *Service) SetActiveOrganization(ctx context.Context, sessionID string, organizationID *string) error {
	// Validate organization exists if ID is provided
	if organizationID != nil && *organizationID != "" {
		_, err := s.GetOrganization(ctx, *organizationID)
		if err != nil {
			return fmt.Errorf("invalid organization: %w", err)
		}
	}

	_, err := s.rawDB.ExecContext(ctx, `UPDATE sessions SET active_organization_id = ? WHERE id = ?`, organizationID, sessionID)
	if err != nil {
		return fmt.Errorf("failed to set active organization: %w", err)
	}

	return nil
}

// SetActiveTeam sets the active team for a session.
// Note: This still uses raw SQL as session table extensions are not yet in sqlc.
func (s *Service) SetActiveTeam(ctx context.Context, sessionID string, teamID *string) error {
	if !s.config.Teams.Enabled {
		return fmt.Errorf("teams are not enabled")
	}

	// Validate team exists if ID is provided
	if teamID != nil && *teamID != "" {
		_, err := s.GetTeam(ctx, *teamID)
		if err != nil {
			return fmt.Errorf("invalid team: %w", err)
		}
	}

	_, err := s.rawDB.ExecContext(ctx, `UPDATE sessions SET active_team_id = ? WHERE id = ?`, teamID, sessionID)
	if err != nil {
		return fmt.Errorf("failed to set active team: %w", err)
	}

	return nil
}

// GetActiveOrganization gets the active organization for a session.
// Note: This still uses raw SQL as session table extensions are not yet in sqlc.
func (s *Service) GetActiveOrganization(ctx context.Context, sessionID string) (*string, error) {
	var activeOrgID *string

	err := s.rawDB.QueryRowContext(ctx, `SELECT active_organization_id FROM sessions WHERE id = ?`, sessionID).Scan(&activeOrgID)
	if err != nil {
		return nil, fmt.Errorf("failed to get active organization: %w", err)
	}

	return activeOrgID, nil
}

// generateID generates a unique ID (simplified implementation).
func generateID() string {
	// In production, use a proper UUID library
	return fmt.Sprintf("org_%d", time.Now().UnixNano())
}
