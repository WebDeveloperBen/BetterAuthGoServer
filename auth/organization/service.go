package organization

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/db"
)

// Service provides organization operations using the database directly.
type Service struct {
	rawDB   db.DBTX
	dialect db.Dialect
	logger  *slog.Logger
	config  *Config
}

// NewService creates a new organization service.
func NewService(rawDB db.DBTX, dialect db.Dialect, logger *slog.Logger, config *Config) *Service {
	return &Service{
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

	// Check organization limit
	var userOrgCount int
	err := s.rawDB.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM organizations o
		JOIN members m ON m.organization_id = o.id
		WHERE m.user_id = ? AND m.role = ?
	`, creatorID, "owner").Scan(&userOrgCount)
	if err != nil {
		return nil, fmt.Errorf("failed to check organization count: %w", err)
	}

	if userOrgCount >= s.config.OrganizationLimit(creatorID) {
		return nil, fmt.Errorf("organization limit exceeded")
	}

	// Check if slug is unique
	var slugExists int
	err = s.rawDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM organizations WHERE slug = ?`, slug).Scan(&slugExists)
	if err != nil {
		return nil, fmt.Errorf("failed to check slug uniqueness: %w", err)
	}
	if slugExists > 0 {
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
	_, err = s.rawDB.ExecContext(ctx, `
		INSERT INTO organizations (id, name, slug, logo, metadata, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, org.ID, org.Name, org.Slug, org.Logo, org.Metadata, s.formatTime(org.CreatedAt), s.formatTime(org.UpdatedAt))
	if err != nil {
		return nil, fmt.Errorf("failed to create organization: %w", err)
	}

	// Add creator as member with appropriate role
	memberID := generateID()
	_, err = s.rawDB.ExecContext(ctx, `
		INSERT INTO members (id, user_id, organization_id, role, created_at)
		VALUES (?, ?, ?, ?, ?)
	`, memberID, creatorID, org.ID, s.config.CreatorRole, s.formatTime(now))
	if err != nil {
		return nil, fmt.Errorf("failed to add creator as member: %w", err)
	}

	// Run after hook
	if s.config.OrganizationHooks.AfterCreateOrganization != nil {
		member, _ := s.GetMember(ctx, org.ID, creatorID)
		if err := s.config.OrganizationHooks.AfterCreateOrganization(org, member, creatorID); err != nil {
			s.logger.Error("after create organization hook failed", "error", err)
		}
	}

	return org, nil
}

// GetOrganization retrieves an organization by ID.
func (s *Service) GetOrganization(ctx context.Context, id string) (*Organization, error) {
	org := &Organization{}
	var createdAt, updatedAt string
	err := s.rawDB.QueryRowContext(ctx, `
		SELECT id, name, slug, logo, metadata, created_at, updated_at
		FROM organizations WHERE id = ?
	`, id).Scan(&org.ID, &org.Name, &org.Slug, &org.Logo, &org.Metadata, &createdAt, &updatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("organization not found")
		}
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}
	org.CreatedAt = s.parseTime(createdAt)
	org.UpdatedAt = s.parseTime(updatedAt)
	return org, nil
}

// GetOrganizationBySlug retrieves an organization by slug.
func (s *Service) GetOrganizationBySlug(ctx context.Context, slug string) (*Organization, error) {
	org := &Organization{}
	var createdAt, updatedAt string
	err := s.rawDB.QueryRowContext(ctx, `
		SELECT id, name, slug, logo, metadata, created_at, updated_at
		FROM organizations WHERE slug = ?
	`, slug).Scan(&org.ID, &org.Name, &org.Slug, &org.Logo, &org.Metadata, &createdAt, &updatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("organization not found")
		}
		return nil, fmt.Errorf("failed to get organization by slug: %w", err)
	}
	org.CreatedAt = s.parseTime(createdAt)
	org.UpdatedAt = s.parseTime(updatedAt)
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
			var slugExists int
			err = s.rawDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM organizations WHERE slug = ? AND id != ?`, slug, id).Scan(&slugExists)
			if err != nil {
				return nil, fmt.Errorf("failed to check slug uniqueness: %w", err)
			}
			if slugExists > 0 {
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

	_, err = s.rawDB.ExecContext(ctx, `
		UPDATE organizations SET name = ?, slug = ?, logo = ?, metadata = ?, updated_at = ?
		WHERE id = ?
	`, org.Name, org.Slug, org.Logo, org.Metadata, s.formatTime(org.UpdatedAt), org.ID)
	if err != nil {
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

	// Delete team members
	if _, err := s.rawDB.ExecContext(ctx, `
		DELETE FROM team_members WHERE team_id IN (SELECT id FROM teams WHERE organization_id = ?)
	`, id); err != nil {
		return fmt.Errorf("failed to delete team members: %w", err)
	}

	// Delete teams
	if _, err := s.rawDB.ExecContext(ctx, `DELETE FROM teams WHERE organization_id = ?`, id); err != nil {
		return fmt.Errorf("failed to delete teams: %w", err)
	}

	// Delete invitations
	if _, err := s.rawDB.ExecContext(ctx, `DELETE FROM invitations WHERE organization_id = ?`, id); err != nil {
		return fmt.Errorf("failed to delete invitations: %w", err)
	}

	// Delete members
	if _, err := s.rawDB.ExecContext(ctx, `DELETE FROM members WHERE organization_id = ?`, id); err != nil {
		return fmt.Errorf("failed to delete members: %w", err)
	}

	// Delete organization
	if _, err := s.rawDB.ExecContext(ctx, `DELETE FROM organizations WHERE id = ?`, id); err != nil {
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
	rows, err := s.rawDB.QueryContext(ctx, `
		SELECT o.id, o.name, o.slug, o.logo, o.metadata, o.created_at, o.updated_at
		FROM organizations o
		JOIN members m ON m.organization_id = o.id
		WHERE m.user_id = ?
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list user organizations: %w", err)
	}
	defer rows.Close()

	var orgs []*Organization
	for rows.Next() {
		org := &Organization{}
		var createdAt, updatedAt string
		if err := rows.Scan(&org.ID, &org.Name, &org.Slug, &org.Logo, &org.Metadata, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan organization: %w", err)
		}
		org.CreatedAt = s.parseTime(createdAt)
		org.UpdatedAt = s.parseTime(updatedAt)
		orgs = append(orgs, org)
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

	member := &Member{
		ID:             generateID(),
		UserID:         userID,
		OrganizationID: organizationID,
		Role:           role,
		CreatedAt:      time.Now(),
	}

	_, err := s.rawDB.ExecContext(ctx, `
		INSERT INTO members (id, user_id, organization_id, role, created_at)
		VALUES (?, ?, ?, ?, ?)
	`, member.ID, member.UserID, member.OrganizationID, member.Role, s.formatTime(member.CreatedAt))
	if err != nil {
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

	_, err := s.rawDB.ExecContext(ctx, `
		DELETE FROM members WHERE organization_id = ? AND user_id = ?
	`, organizationID, userID)
	if err != nil {
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

	member.Role = role

	_, err = s.rawDB.ExecContext(ctx, `UPDATE members SET role = ? WHERE id = ?`, role, member.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to update member role: %w", err)
	}

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
	member := &Member{}
	var createdAt string
	err := s.rawDB.QueryRowContext(ctx, `
		SELECT id, user_id, organization_id, role, created_at
		FROM members WHERE organization_id = ? AND user_id = ?
	`, organizationID, userID).Scan(&member.ID, &member.UserID, &member.OrganizationID, &member.Role, &createdAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("member not found")
		}
		return nil, fmt.Errorf("failed to get member: %w", err)
	}
	member.CreatedAt = s.parseTime(createdAt)
	return member, nil
}

// ListMembers lists all members of an organization.
func (s *Service) ListMembers(ctx context.Context, organizationID string) ([]*Member, error) {
	rows, err := s.rawDB.QueryContext(ctx, `
		SELECT id, user_id, organization_id, role, created_at
		FROM members WHERE organization_id = ?
	`, organizationID)
	if err != nil {
		return nil, fmt.Errorf("failed to list members: %w", err)
	}
	defer rows.Close()

	var members []*Member
	for rows.Next() {
		member := &Member{}
		var createdAt string
		if err := rows.Scan(&member.ID, &member.UserID, &member.OrganizationID, &member.Role, &createdAt); err != nil {
			return nil, fmt.Errorf("failed to scan member: %w", err)
		}
		member.CreatedAt = s.parseTime(createdAt)
		members = append(members, member)
	}
	return members, nil
}

// GetActiveMember gets the user's active member record.
func (s *Service) GetActiveMember(ctx context.Context, userID string) (*Member, error) {
	member := &Member{}
	var createdAt string
	err := s.rawDB.QueryRowContext(ctx, `
		SELECT id, user_id, organization_id, role, created_at
		FROM members WHERE user_id = ? LIMIT 1
	`, userID).Scan(&member.ID, &member.UserID, &member.OrganizationID, &member.Role, &createdAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no membership found")
		}
		return nil, fmt.Errorf("failed to get active member: %w", err)
	}
	member.CreatedAt = s.parseTime(createdAt)
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

	_, err := s.rawDB.ExecContext(ctx, `
		INSERT INTO invitations (id, email, organization_id, inviter_id, role, status, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, invitation.ID, invitation.Email, invitation.OrganizationID, invitation.InviterID,
		invitation.Role, invitation.Status, s.formatTimePtr(invitation.ExpiresAt), s.formatTime(invitation.CreatedAt))
	if err != nil {
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
	member := &Member{
		ID:             generateID(),
		UserID:         userID,
		OrganizationID: invitation.OrganizationID,
		Role:           invitation.Role,
		CreatedAt:      time.Now(),
	}

	_, err = s.rawDB.ExecContext(ctx, `
		INSERT INTO members (id, user_id, organization_id, role, created_at)
		VALUES (?, ?, ?, ?, ?)
	`, member.ID, member.UserID, member.OrganizationID, member.Role, s.formatTime(member.CreatedAt))
	if err != nil {
		return nil, fmt.Errorf("failed to add member: %w", err)
	}

	// Update invitation status
	_, err = s.rawDB.ExecContext(ctx, `UPDATE invitations SET status = ? WHERE id = ?`, "accepted", invitationID)
	if err != nil {
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

	_, err = s.rawDB.ExecContext(ctx, `UPDATE invitations SET status = ? WHERE id = ?`, "rejected", invitationID)
	if err != nil {
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

	_, err = s.rawDB.ExecContext(ctx, `UPDATE invitations SET status = ? WHERE id = ?`, "cancelled", invitationID)
	if err != nil {
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
	rows, err := s.rawDB.QueryContext(ctx, `
		SELECT id, email, organization_id, inviter_id, role, status, expires_at, created_at
		FROM invitations WHERE organization_id = ?
	`, organizationID)
	if err != nil {
		return nil, fmt.Errorf("failed to list invitations: %w", err)
	}
	defer rows.Close()

	var invitations []*Invitation
	for rows.Next() {
		inv := &Invitation{}
		var expiresAt, createdAt sql.NullString
		if err := rows.Scan(&inv.ID, &inv.Email, &inv.OrganizationID, &inv.InviterID,
			&inv.Role, &inv.Status, &expiresAt, &createdAt); err != nil {
			return nil, fmt.Errorf("failed to scan invitation: %w", err)
		}
		if expiresAt.Valid {
			t := s.parseTime(expiresAt.String)
			inv.ExpiresAt = &t
		}
		if createdAt.Valid {
			inv.CreatedAt = s.parseTime(createdAt.String)
		}
		invitations = append(invitations, inv)
	}
	return invitations, nil
}

// GetInvitation retrieves an invitation by ID.
func (s *Service) GetInvitation(ctx context.Context, id string) (*Invitation, error) {
	inv := &Invitation{}
	var expiresAt, createdAt sql.NullString
	err := s.rawDB.QueryRowContext(ctx, `
		SELECT id, email, organization_id, inviter_id, role, status, expires_at, created_at
		FROM invitations WHERE id = ?
	`, id).Scan(&inv.ID, &inv.Email, &inv.OrganizationID, &inv.InviterID,
		&inv.Role, &inv.Status, &expiresAt, &createdAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("invitation not found")
		}
		return nil, fmt.Errorf("failed to get invitation: %w", err)
	}
	if expiresAt.Valid {
		t := s.parseTime(expiresAt.String)
		inv.ExpiresAt = &t
	}
	if createdAt.Valid {
		inv.CreatedAt = s.parseTime(createdAt.String)
	}
	return inv, nil
}

// ListUserInvitations lists pending invitations for a user by email.
func (s *Service) ListUserInvitations(ctx context.Context, email string) ([]*Invitation, error) {
	rows, err := s.rawDB.QueryContext(ctx, `
		SELECT id, email, organization_id, inviter_id, role, status, expires_at, created_at
		FROM invitations WHERE email = ? AND status = ?
	`, email, "pending")
	if err != nil {
		return nil, fmt.Errorf("failed to list user invitations: %w", err)
	}
	defer rows.Close()

	var invitations []*Invitation
	for rows.Next() {
		inv := &Invitation{}
		var expiresAt, createdAt sql.NullString
		if err := rows.Scan(&inv.ID, &inv.Email, &inv.OrganizationID, &inv.InviterID,
			&inv.Role, &inv.Status, &expiresAt, &createdAt); err != nil {
			return nil, fmt.Errorf("failed to scan invitation: %w", err)
		}
		if expiresAt.Valid {
			t := s.parseTime(expiresAt.String)
			inv.ExpiresAt = &t
		}
		if createdAt.Valid {
			inv.CreatedAt = s.parseTime(createdAt.String)
		}
		invitations = append(invitations, inv)
	}
	return invitations, nil
}

// CreateTeam creates a new team (if teams are enabled).
func (s *Service) CreateTeam(ctx context.Context, organizationID, name string) (*Team, error) {
	if !s.config.Teams.Enabled {
		return nil, fmt.Errorf("teams are not enabled")
	}

	team := &Team{
		ID:             generateID(),
		Name:           name,
		OrganizationID: organizationID,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	_, err := s.rawDB.ExecContext(ctx, `
		INSERT INTO teams (id, name, organization_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
	`, team.ID, team.Name, team.OrganizationID, s.formatTime(team.CreatedAt), s.formatTime(team.UpdatedAt))
	if err != nil {
		return nil, fmt.Errorf("failed to create team: %w", err)
	}

	return team, nil
}

// GetTeam retrieves a team by ID.
func (s *Service) GetTeam(ctx context.Context, teamID string) (*Team, error) {
	team := &Team{}
	var createdAt, updatedAt string
	err := s.rawDB.QueryRowContext(ctx, `
		SELECT id, name, organization_id, created_at, updated_at
		FROM teams WHERE id = ?
	`, teamID).Scan(&team.ID, &team.Name, &team.OrganizationID, &createdAt, &updatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("team not found")
		}
		return nil, fmt.Errorf("failed to get team: %w", err)
	}
	team.CreatedAt = s.parseTime(createdAt)
	team.UpdatedAt = s.parseTime(updatedAt)
	return team, nil
}

// UpdateTeam updates a team.
func (s *Service) UpdateTeam(ctx context.Context, teamID, name string) (*Team, error) {
	team, err := s.GetTeam(ctx, teamID)
	if err != nil {
		return nil, err
	}

	team.Name = name
	team.UpdatedAt = time.Now()

	_, err = s.rawDB.ExecContext(ctx, `UPDATE teams SET name = ?, updated_at = ? WHERE id = ?`,
		team.Name, s.formatTime(team.UpdatedAt), team.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to update team: %w", err)
	}

	return team, nil
}

// DeleteTeam deletes a team.
func (s *Service) DeleteTeam(ctx context.Context, teamID string) error {
	_, err := s.rawDB.ExecContext(ctx, `DELETE FROM teams WHERE id = ?`, teamID)
	return err
}

// ListTeams lists teams for an organization.
func (s *Service) ListTeams(ctx context.Context, organizationID string) ([]*Team, error) {
	rows, err := s.rawDB.QueryContext(ctx, `
		SELECT id, name, organization_id, created_at, updated_at
		FROM teams WHERE organization_id = ?
	`, organizationID)
	if err != nil {
		return nil, fmt.Errorf("failed to list teams: %w", err)
	}
	defer rows.Close()

	var teams []*Team
	for rows.Next() {
		team := &Team{}
		var createdAt, updatedAt string
		if err := rows.Scan(&team.ID, &team.Name, &team.OrganizationID, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan team: %w", err)
		}
		team.CreatedAt = s.parseTime(createdAt)
		team.UpdatedAt = s.parseTime(updatedAt)
		teams = append(teams, team)
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

	_, err := s.rawDB.ExecContext(ctx, `
		INSERT INTO team_members (id, team_id, user_id, created_at)
		VALUES (?, ?, ?, ?)
	`, teamMember.ID, teamMember.TeamID, teamMember.UserID, s.formatTime(teamMember.CreatedAt))
	if err != nil {
		return nil, fmt.Errorf("failed to add team member: %w", err)
	}

	return teamMember, nil
}

// RemoveTeamMember removes a user from a team.
func (s *Service) RemoveTeamMember(ctx context.Context, teamID, userID string) error {
	_, err := s.rawDB.ExecContext(ctx, `DELETE FROM team_members WHERE team_id = ? AND user_id = ?`, teamID, userID)
	return err
}

// ListTeamMembers lists members of a team.
func (s *Service) ListTeamMembers(ctx context.Context, teamID string) ([]*TeamMember, error) {
	rows, err := s.rawDB.QueryContext(ctx, `
		SELECT id, team_id, user_id, created_at
		FROM team_members WHERE team_id = ?
	`, teamID)
	if err != nil {
		return nil, fmt.Errorf("failed to list team members: %w", err)
	}
	defer rows.Close()

	var members []*TeamMember
	for rows.Next() {
		member := &TeamMember{}
		var createdAt string
		if err := rows.Scan(&member.ID, &member.TeamID, &member.UserID, &createdAt); err != nil {
			return nil, fmt.Errorf("failed to scan team member: %w", err)
		}
		member.CreatedAt = s.parseTime(createdAt)
		members = append(members, member)
	}
	return members, nil
}

// SetActiveOrganization sets the active organization for a session.
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
func (s *Service) GetActiveOrganization(ctx context.Context, sessionID string) (*string, error) {
	var activeOrgID sql.NullString

	err := s.rawDB.QueryRowContext(ctx, `SELECT active_organization_id FROM sessions WHERE id = ?`, sessionID).Scan(&activeOrgID)
	if err != nil {
		return nil, fmt.Errorf("failed to get active organization: %w", err)
	}

	if !activeOrgID.Valid {
		return nil, nil
	}

	return &activeOrgID.String, nil
}

// Helper methods for time formatting based on dialect

func (s *Service) formatTime(t time.Time) string {
	if s.dialect == db.DialectPostgres {
		return t.Format(time.RFC3339)
	}
	return t.Format(time.RFC3339)
}

func (s *Service) formatTimePtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	str := s.formatTime(*t)
	return &str
}

func (s *Service) parseTime(str string) time.Time {
	t, _ := time.Parse(time.RFC3339, str)
	return t
}

// generateID generates a unique ID (simplified implementation).
func generateID() string {
	// In production, use a proper UUID library
	return fmt.Sprintf("org_%d", time.Now().UnixNano())
}
