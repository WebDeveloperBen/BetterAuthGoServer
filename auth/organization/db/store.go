// Package db provides database storage implementations for organization management.
package db

import (
	"context"
	"database/sql"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/organization/db/pgstore"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/organization/db/sqlitestore"
	coredb "github.com/webdeveloperben/BetterAuthGoServer/db"
)

// Organization represents an organization.
type Organization struct {
	ID        string
	Name      string
	Slug      string
	Logo      *string
	Metadata  *string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Member represents a member of an organization.
type Member struct {
	ID             string
	OrganizationID string
	UserID         string
	Role           string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// Invitation represents an invitation to join an organization.
type Invitation struct {
	ID             string
	Email          string
	OrganizationID string
	InviterID      string
	Role           string
	Status         string
	ExpiresAt      *time.Time
	CreatedAt      time.Time
}

// Team represents a team within an organization.
type Team struct {
	ID             string
	Name           string
	OrganizationID string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// TeamMember represents a member of a team.
type TeamMember struct {
	ID        string
	TeamID    string
	UserID    string
	CreatedAt time.Time
}

// Store wraps the sqlc-generated queries for organization operations.
type Store struct {
	dialect coredb.Dialect
	pgQ     *pgstore.Queries
	sqliteQ *sqlitestore.Queries
}

// New creates a new Store for organization operations.
func New(db coredb.DBTX, dialect coredb.Dialect) *Store {
	s := &Store{dialect: dialect}
	if dialect == coredb.DialectPostgres {
		s.pgQ = pgstore.New(db)
	} else {
		s.sqliteQ = sqlitestore.New(db)
	}
	return s
}

// =============================================================================
// Organization operations
// =============================================================================

// CreateOrganization creates a new organization.
func (s *Store) CreateOrganization(ctx context.Context, org *Organization) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.CreateOrganization(ctx, pgstore.CreateOrganizationParams{
			ID:        org.ID,
			Name:      org.Name,
			Slug:      org.Slug,
			Logo:      toNullString(org.Logo),
			Metadata:  toNullString(org.Metadata),
			CreatedAt: org.CreatedAt,
			UpdatedAt: org.UpdatedAt,
		})
	}
	return s.sqliteQ.CreateOrganization(ctx, sqlitestore.CreateOrganizationParams{
		ID:        org.ID,
		Name:      org.Name,
		Slug:      org.Slug,
		Logo:      toNullString(org.Logo),
		Metadata:  toNullString(org.Metadata),
		CreatedAt: org.CreatedAt.Format(time.RFC3339),
		UpdatedAt: org.UpdatedAt.Format(time.RFC3339),
	})
}

// GetOrganizationByID retrieves an organization by ID.
func (s *Store) GetOrganizationByID(ctx context.Context, id string) (*Organization, error) {
	if s.dialect == coredb.DialectPostgres {
		row, err := s.pgQ.GetOrganizationByID(ctx, id)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, nil
			}
			return nil, err
		}
		return pgOrgToDomain(&row), nil
	}
	row, err := s.sqliteQ.GetOrganizationByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteOrgToDomain(&row), nil
}

// GetOrganizationBySlug retrieves an organization by slug.
func (s *Store) GetOrganizationBySlug(ctx context.Context, slug string) (*Organization, error) {
	if s.dialect == coredb.DialectPostgres {
		row, err := s.pgQ.GetOrganizationBySlug(ctx, slug)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, nil
			}
			return nil, err
		}
		return pgOrgToDomain(&row), nil
	}
	row, err := s.sqliteQ.GetOrganizationBySlug(ctx, slug)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteOrgToDomain(&row), nil
}

// UpdateOrganization updates an organization.
func (s *Store) UpdateOrganization(ctx context.Context, org *Organization) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.UpdateOrganization(ctx, pgstore.UpdateOrganizationParams{
			ID:        org.ID,
			Name:      org.Name,
			Slug:      org.Slug,
			Logo:      toNullString(org.Logo),
			Metadata:  toNullString(org.Metadata),
			UpdatedAt: org.UpdatedAt,
		})
	}
	return s.sqliteQ.UpdateOrganization(ctx, sqlitestore.UpdateOrganizationParams{
		ID:        org.ID,
		Name:      org.Name,
		Slug:      org.Slug,
		Logo:      toNullString(org.Logo),
		Metadata:  toNullString(org.Metadata),
		UpdatedAt: org.UpdatedAt.Format(time.RFC3339),
	})
}

// DeleteOrganization deletes an organization.
func (s *Store) DeleteOrganization(ctx context.Context, id string) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.DeleteOrganization(ctx, id)
	}
	return s.sqliteQ.DeleteOrganization(ctx, id)
}

// ListUserOrganizations lists organizations a user belongs to.
func (s *Store) ListUserOrganizations(ctx context.Context, userID string) ([]*Organization, error) {
	if s.dialect == coredb.DialectPostgres {
		rows, err := s.pgQ.ListUserOrganizations(ctx, userID)
		if err != nil {
			return nil, err
		}
		orgs := make([]*Organization, len(rows))
		for i, row := range rows {
			r := row
			orgs[i] = pgOrgToDomain(&r)
		}
		return orgs, nil
	}
	rows, err := s.sqliteQ.ListUserOrganizations(ctx, userID)
	if err != nil {
		return nil, err
	}
	orgs := make([]*Organization, len(rows))
	for i, row := range rows {
		r := row
		orgs[i] = sqliteOrgToDomain(&r)
	}
	return orgs, nil
}

// CheckSlugExists checks if an organization slug exists.
func (s *Store) CheckSlugExists(ctx context.Context, slug string) (bool, error) {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.CheckSlugExists(ctx, slug)
	}
	return s.sqliteQ.CheckSlugExists(ctx, slug)
}

// =============================================================================
// Member operations
// =============================================================================

// CreateMember creates a new member.
func (s *Store) CreateMember(ctx context.Context, member *Member) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.CreateMember(ctx, pgstore.CreateMemberParams{
			ID:             member.ID,
			OrganizationID: member.OrganizationID,
			UserID:         member.UserID,
			Role:           member.Role,
			CreatedAt:      member.CreatedAt,
			UpdatedAt:      member.UpdatedAt,
		})
	}
	return s.sqliteQ.CreateMember(ctx, sqlitestore.CreateMemberParams{
		ID:             member.ID,
		OrganizationID: member.OrganizationID,
		UserID:         member.UserID,
		Role:           member.Role,
		CreatedAt:      member.CreatedAt.Format(time.RFC3339),
		UpdatedAt:      member.UpdatedAt.Format(time.RFC3339),
	})
}

// GetMember retrieves a member by organization and user ID.
func (s *Store) GetMember(ctx context.Context, orgID, userID string) (*Member, error) {
	if s.dialect == coredb.DialectPostgres {
		row, err := s.pgQ.GetMember(ctx, pgstore.GetMemberParams{
			OrganizationID: orgID,
			UserID:         userID,
		})
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, nil
			}
			return nil, err
		}
		return pgMemberToDomain(&row), nil
	}
	row, err := s.sqliteQ.GetMember(ctx, sqlitestore.GetMemberParams{
		OrganizationID: orgID,
		UserID:         userID,
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteMemberToDomain(&row), nil
}

// GetMemberByID retrieves a member by ID.
func (s *Store) GetMemberByID(ctx context.Context, id string) (*Member, error) {
	if s.dialect == coredb.DialectPostgres {
		row, err := s.pgQ.GetMemberByID(ctx, id)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, nil
			}
			return nil, err
		}
		return pgMemberToDomain(&row), nil
	}
	row, err := s.sqliteQ.GetMemberByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteMemberToDomain(&row), nil
}

// ListMembersByOrganization lists members of an organization.
func (s *Store) ListMembersByOrganization(ctx context.Context, orgID string) ([]*Member, error) {
	if s.dialect == coredb.DialectPostgres {
		rows, err := s.pgQ.ListMembersByOrganization(ctx, orgID)
		if err != nil {
			return nil, err
		}
		members := make([]*Member, len(rows))
		for i, row := range rows {
			r := row
			members[i] = pgMemberToDomain(&r)
		}
		return members, nil
	}
	rows, err := s.sqliteQ.ListMembersByOrganization(ctx, orgID)
	if err != nil {
		return nil, err
	}
	members := make([]*Member, len(rows))
	for i, row := range rows {
		r := row
		members[i] = sqliteMemberToDomain(&r)
	}
	return members, nil
}

// ListMembersByUser lists memberships of a user.
func (s *Store) ListMembersByUser(ctx context.Context, userID string) ([]*Member, error) {
	if s.dialect == coredb.DialectPostgres {
		rows, err := s.pgQ.ListMembersByUser(ctx, userID)
		if err != nil {
			return nil, err
		}
		members := make([]*Member, len(rows))
		for i, row := range rows {
			r := row
			members[i] = pgMemberToDomain(&r)
		}
		return members, nil
	}
	rows, err := s.sqliteQ.ListMembersByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	members := make([]*Member, len(rows))
	for i, row := range rows {
		r := row
		members[i] = sqliteMemberToDomain(&r)
	}
	return members, nil
}

// UpdateMemberRole updates a member's role.
func (s *Store) UpdateMemberRole(ctx context.Context, id, role string, updatedAt time.Time) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.UpdateMemberRole(ctx, pgstore.UpdateMemberRoleParams{
			ID:        id,
			Role:      role,
			UpdatedAt: updatedAt,
		})
	}
	return s.sqliteQ.UpdateMemberRole(ctx, sqlitestore.UpdateMemberRoleParams{
		ID:        id,
		Role:      role,
		UpdatedAt: updatedAt.Format(time.RFC3339),
	})
}

// DeleteMember removes a member.
func (s *Store) DeleteMember(ctx context.Context, orgID, userID string) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.DeleteMember(ctx, pgstore.DeleteMemberParams{
			OrganizationID: orgID,
			UserID:         userID,
		})
	}
	return s.sqliteQ.DeleteMember(ctx, sqlitestore.DeleteMemberParams{
		OrganizationID: orgID,
		UserID:         userID,
	})
}

// CountOrganizationMembers counts the members in an organization.
func (s *Store) CountOrganizationMembers(ctx context.Context, orgID string) (int64, error) {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.CountOrganizationMembers(ctx, orgID)
	}
	return s.sqliteQ.CountOrganizationMembers(ctx, orgID)
}

// GetFirstMemberByUser gets the first membership for a user.
func (s *Store) GetFirstMemberByUser(ctx context.Context, userID string) (*Member, error) {
	if s.dialect == coredb.DialectPostgres {
		row, err := s.pgQ.GetFirstMemberByUser(ctx, userID)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, nil
			}
			return nil, err
		}
		return pgMemberToDomain(&row), nil
	}
	row, err := s.sqliteQ.GetFirstMemberByUser(ctx, userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteMemberToDomain(&row), nil
}

// =============================================================================
// Invitation operations
// =============================================================================

// CreateInvitation creates a new invitation.
func (s *Store) CreateInvitation(ctx context.Context, inv *Invitation) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.CreateInvitation(ctx, pgstore.CreateInvitationParams{
			ID:             inv.ID,
			Email:          inv.Email,
			OrganizationID: inv.OrganizationID,
			InviterID:      inv.InviterID,
			Role:           inv.Role,
			Status:         inv.Status,
			ExpiresAt:      toNullTime(inv.ExpiresAt),
			CreatedAt:      inv.CreatedAt,
		})
	}
	return s.sqliteQ.CreateInvitation(ctx, sqlitestore.CreateInvitationParams{
		ID:             inv.ID,
		Email:          inv.Email,
		OrganizationID: inv.OrganizationID,
		InviterID:      inv.InviterID,
		Role:           inv.Role,
		Status:         inv.Status,
		ExpiresAt:      timeToNullString(inv.ExpiresAt),
		CreatedAt:      inv.CreatedAt.Format(time.RFC3339),
	})
}

// GetInvitationByID retrieves an invitation by ID.
func (s *Store) GetInvitationByID(ctx context.Context, id string) (*Invitation, error) {
	if s.dialect == coredb.DialectPostgres {
		row, err := s.pgQ.GetInvitationByID(ctx, id)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, nil
			}
			return nil, err
		}
		return pgInvitationToDomain(&row), nil
	}
	row, err := s.sqliteQ.GetInvitationByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteInvitationToDomain(&row), nil
}

// GetPendingInvitationByEmailAndOrg retrieves a pending invitation.
func (s *Store) GetPendingInvitationByEmailAndOrg(ctx context.Context, email, orgID string) (*Invitation, error) {
	if s.dialect == coredb.DialectPostgres {
		row, err := s.pgQ.GetInvitationByEmailAndOrg(ctx, pgstore.GetInvitationByEmailAndOrgParams{
			Email:          email,
			OrganizationID: orgID,
		})
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, nil
			}
			return nil, err
		}
		return pgInvitationToDomain(&row), nil
	}
	row, err := s.sqliteQ.GetInvitationByEmailAndOrg(ctx, sqlitestore.GetInvitationByEmailAndOrgParams{
		Email:          email,
		OrganizationID: orgID,
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteInvitationToDomain(&row), nil
}

// ListInvitationsByOrganization lists invitations for an organization.
func (s *Store) ListInvitationsByOrganization(ctx context.Context, orgID string) ([]*Invitation, error) {
	if s.dialect == coredb.DialectPostgres {
		rows, err := s.pgQ.ListInvitationsByOrganization(ctx, orgID)
		if err != nil {
			return nil, err
		}
		invs := make([]*Invitation, len(rows))
		for i, row := range rows {
			r := row
			invs[i] = pgInvitationToDomain(&r)
		}
		return invs, nil
	}
	rows, err := s.sqliteQ.ListInvitationsByOrganization(ctx, orgID)
	if err != nil {
		return nil, err
	}
	invs := make([]*Invitation, len(rows))
	for i, row := range rows {
		r := row
		invs[i] = sqliteInvitationToDomain(&r)
	}
	return invs, nil
}

// ListPendingInvitationsByEmail lists pending invitations for an email.
func (s *Store) ListPendingInvitationsByEmail(ctx context.Context, email string) ([]*Invitation, error) {
	if s.dialect == coredb.DialectPostgres {
		rows, err := s.pgQ.ListInvitationsByEmail(ctx, email)
		if err != nil {
			return nil, err
		}
		invs := make([]*Invitation, len(rows))
		for i, row := range rows {
			r := row
			invs[i] = pgInvitationToDomain(&r)
		}
		return invs, nil
	}
	rows, err := s.sqliteQ.ListInvitationsByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	invs := make([]*Invitation, len(rows))
	for i, row := range rows {
		r := row
		invs[i] = sqliteInvitationToDomain(&r)
	}
	return invs, nil
}

// UpdateInvitationStatus updates an invitation's status.
func (s *Store) UpdateInvitationStatus(ctx context.Context, id, status string) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.UpdateInvitationStatus(ctx, pgstore.UpdateInvitationStatusParams{
			ID:     id,
			Status: status,
		})
	}
	return s.sqliteQ.UpdateInvitationStatus(ctx, sqlitestore.UpdateInvitationStatusParams{
		ID:     id,
		Status: status,
	})
}

// CancelPendingInvitations cancels pending invitations.
func (s *Store) CancelPendingInvitations(ctx context.Context, email, orgID string) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.CancelPendingInvitations(ctx, pgstore.CancelPendingInvitationsParams{
			Email:          email,
			OrganizationID: orgID,
		})
	}
	return s.sqliteQ.CancelPendingInvitations(ctx, sqlitestore.CancelPendingInvitationsParams{
		Email:          email,
		OrganizationID: orgID,
	})
}

// DeleteExpiredInvitations removes expired invitations.
func (s *Store) DeleteExpiredInvitations(ctx context.Context) (int64, error) {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.DeleteExpiredInvitations(ctx)
	}
	return s.sqliteQ.DeleteExpiredInvitations(ctx)
}

// =============================================================================
// Team operations
// =============================================================================

// CreateTeam creates a new team.
func (s *Store) CreateTeam(ctx context.Context, team *Team) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.CreateTeam(ctx, pgstore.CreateTeamParams{
			ID:             team.ID,
			Name:           team.Name,
			OrganizationID: team.OrganizationID,
			CreatedAt:      team.CreatedAt,
			UpdatedAt:      team.UpdatedAt,
		})
	}
	return s.sqliteQ.CreateTeam(ctx, sqlitestore.CreateTeamParams{
		ID:             team.ID,
		Name:           team.Name,
		OrganizationID: team.OrganizationID,
		CreatedAt:      team.CreatedAt.Format(time.RFC3339),
		UpdatedAt:      team.UpdatedAt.Format(time.RFC3339),
	})
}

// GetTeamByID retrieves a team by ID.
func (s *Store) GetTeamByID(ctx context.Context, id string) (*Team, error) {
	if s.dialect == coredb.DialectPostgres {
		row, err := s.pgQ.GetTeamByID(ctx, id)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, nil
			}
			return nil, err
		}
		return pgTeamToDomain(&row), nil
	}
	row, err := s.sqliteQ.GetTeamByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteTeamToDomain(&row), nil
}

// ListTeamsByOrganization lists teams in an organization.
func (s *Store) ListTeamsByOrganization(ctx context.Context, orgID string) ([]*Team, error) {
	if s.dialect == coredb.DialectPostgres {
		rows, err := s.pgQ.ListTeamsByOrganization(ctx, orgID)
		if err != nil {
			return nil, err
		}
		teams := make([]*Team, len(rows))
		for i, row := range rows {
			r := row
			teams[i] = pgTeamToDomain(&r)
		}
		return teams, nil
	}
	rows, err := s.sqliteQ.ListTeamsByOrganization(ctx, orgID)
	if err != nil {
		return nil, err
	}
	teams := make([]*Team, len(rows))
	for i, row := range rows {
		r := row
		teams[i] = sqliteTeamToDomain(&r)
	}
	return teams, nil
}

// UpdateTeam updates a team.
func (s *Store) UpdateTeam(ctx context.Context, id, name string, updatedAt time.Time) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.UpdateTeam(ctx, pgstore.UpdateTeamParams{
			ID:        id,
			Name:      name,
			UpdatedAt: updatedAt,
		})
	}
	return s.sqliteQ.UpdateTeam(ctx, sqlitestore.UpdateTeamParams{
		ID:        id,
		Name:      name,
		UpdatedAt: updatedAt.Format(time.RFC3339),
	})
}

// DeleteTeam deletes a team.
func (s *Store) DeleteTeam(ctx context.Context, id string) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.DeleteTeam(ctx, id)
	}
	return s.sqliteQ.DeleteTeam(ctx, id)
}

// =============================================================================
// Team Member operations
// =============================================================================

// CreateTeamMember adds a member to a team.
func (s *Store) CreateTeamMember(ctx context.Context, member *TeamMember) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.CreateTeamMember(ctx, pgstore.CreateTeamMemberParams{
			ID:        member.ID,
			TeamID:    member.TeamID,
			UserID:    member.UserID,
			CreatedAt: member.CreatedAt,
		})
	}
	return s.sqliteQ.CreateTeamMember(ctx, sqlitestore.CreateTeamMemberParams{
		ID:        member.ID,
		TeamID:    member.TeamID,
		UserID:    member.UserID,
		CreatedAt: member.CreatedAt.Format(time.RFC3339),
	})
}

// GetTeamMember retrieves a team member.
func (s *Store) GetTeamMember(ctx context.Context, teamID, userID string) (*TeamMember, error) {
	if s.dialect == coredb.DialectPostgres {
		row, err := s.pgQ.GetTeamMember(ctx, pgstore.GetTeamMemberParams{
			TeamID: teamID,
			UserID: userID,
		})
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, nil
			}
			return nil, err
		}
		return pgTeamMemberToDomain(&row), nil
	}
	row, err := s.sqliteQ.GetTeamMember(ctx, sqlitestore.GetTeamMemberParams{
		TeamID: teamID,
		UserID: userID,
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteTeamMemberToDomain(&row), nil
}

// ListTeamMembersByTeam lists members of a team.
func (s *Store) ListTeamMembersByTeam(ctx context.Context, teamID string) ([]*TeamMember, error) {
	if s.dialect == coredb.DialectPostgres {
		rows, err := s.pgQ.ListTeamMembersByTeam(ctx, teamID)
		if err != nil {
			return nil, err
		}
		members := make([]*TeamMember, len(rows))
		for i, row := range rows {
			r := row
			members[i] = pgTeamMemberToDomain(&r)
		}
		return members, nil
	}
	rows, err := s.sqliteQ.ListTeamMembersByTeam(ctx, teamID)
	if err != nil {
		return nil, err
	}
	members := make([]*TeamMember, len(rows))
	for i, row := range rows {
		r := row
		members[i] = sqliteTeamMemberToDomain(&r)
	}
	return members, nil
}

// ListTeamMembersByUser lists team memberships of a user.
func (s *Store) ListTeamMembersByUser(ctx context.Context, userID string) ([]*TeamMember, error) {
	if s.dialect == coredb.DialectPostgres {
		rows, err := s.pgQ.ListTeamMembersByUser(ctx, userID)
		if err != nil {
			return nil, err
		}
		members := make([]*TeamMember, len(rows))
		for i, row := range rows {
			r := row
			members[i] = pgTeamMemberToDomain(&r)
		}
		return members, nil
	}
	rows, err := s.sqliteQ.ListTeamMembersByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	members := make([]*TeamMember, len(rows))
	for i, row := range rows {
		r := row
		members[i] = sqliteTeamMemberToDomain(&r)
	}
	return members, nil
}

// DeleteTeamMember removes a member from a team.
func (s *Store) DeleteTeamMember(ctx context.Context, teamID, userID string) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.DeleteTeamMember(ctx, pgstore.DeleteTeamMemberParams{
			TeamID: teamID,
			UserID: userID,
		})
	}
	return s.sqliteQ.DeleteTeamMember(ctx, sqlitestore.DeleteTeamMemberParams{
		TeamID: teamID,
		UserID: userID,
	})
}

// =============================================================================
// Conversion helpers
// =============================================================================

func toNullString(s *string) sql.NullString {
	if s == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *s, Valid: true}
}

func fromNullString(ns sql.NullString) *string {
	if !ns.Valid {
		return nil
	}
	return &ns.String
}

func toNullTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}

func fromNullTime(nt sql.NullTime) *time.Time {
	if !nt.Valid {
		return nil
	}
	return &nt.Time
}

func timeToNullString(t *time.Time) sql.NullString {
	if t == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: t.Format(time.RFC3339), Valid: true}
}

func nullStringToTime(ns sql.NullString) *time.Time {
	if !ns.Valid || ns.String == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, ns.String)
	if err != nil {
		return nil
	}
	return &t
}

// PostgreSQL domain converters
func pgOrgToDomain(row *pgstore.Organization) *Organization {
	return &Organization{
		ID:        row.ID,
		Name:      row.Name,
		Slug:      row.Slug,
		Logo:      fromNullString(row.Logo),
		Metadata:  fromNullString(row.Metadata),
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}
}

func pgMemberToDomain(row *pgstore.Member) *Member {
	return &Member{
		ID:             row.ID,
		OrganizationID: row.OrganizationID,
		UserID:         row.UserID,
		Role:           row.Role,
		CreatedAt:      row.CreatedAt,
		UpdatedAt:      row.UpdatedAt,
	}
}

func pgInvitationToDomain(row *pgstore.Invitation) *Invitation {
	return &Invitation{
		ID:             row.ID,
		Email:          row.Email,
		OrganizationID: row.OrganizationID,
		InviterID:      row.InviterID,
		Role:           row.Role,
		Status:         row.Status,
		ExpiresAt:      fromNullTime(row.ExpiresAt),
		CreatedAt:      row.CreatedAt,
	}
}

func pgTeamToDomain(row *pgstore.Team) *Team {
	return &Team{
		ID:             row.ID,
		Name:           row.Name,
		OrganizationID: row.OrganizationID,
		CreatedAt:      row.CreatedAt,
		UpdatedAt:      row.UpdatedAt,
	}
}

func pgTeamMemberToDomain(row *pgstore.TeamMember) *TeamMember {
	return &TeamMember{
		ID:        row.ID,
		TeamID:    row.TeamID,
		UserID:    row.UserID,
		CreatedAt: row.CreatedAt,
	}
}

// SQLite domain converters
func sqliteOrgToDomain(row *sqlitestore.Organization) *Organization {
	org := &Organization{
		ID:       row.ID,
		Name:     row.Name,
		Slug:     row.Slug,
		Logo:     fromNullString(row.Logo),
		Metadata: fromNullString(row.Metadata),
	}
	if t, err := time.Parse(time.RFC3339, row.CreatedAt); err == nil {
		org.CreatedAt = t
	}
	if t, err := time.Parse(time.RFC3339, row.UpdatedAt); err == nil {
		org.UpdatedAt = t
	}
	return org
}

func sqliteMemberToDomain(row *sqlitestore.Member) *Member {
	member := &Member{
		ID:             row.ID,
		OrganizationID: row.OrganizationID,
		UserID:         row.UserID,
		Role:           row.Role,
	}
	if t, err := time.Parse(time.RFC3339, row.CreatedAt); err == nil {
		member.CreatedAt = t
	}
	if t, err := time.Parse(time.RFC3339, row.UpdatedAt); err == nil {
		member.UpdatedAt = t
	}
	return member
}

func sqliteInvitationToDomain(row *sqlitestore.Invitation) *Invitation {
	inv := &Invitation{
		ID:             row.ID,
		Email:          row.Email,
		OrganizationID: row.OrganizationID,
		InviterID:      row.InviterID,
		Role:           row.Role,
		Status:         row.Status,
		ExpiresAt:      nullStringToTime(row.ExpiresAt),
	}
	if t, err := time.Parse(time.RFC3339, row.CreatedAt); err == nil {
		inv.CreatedAt = t
	}
	return inv
}

func sqliteTeamToDomain(row *sqlitestore.Team) *Team {
	team := &Team{
		ID:             row.ID,
		Name:           row.Name,
		OrganizationID: row.OrganizationID,
	}
	if t, err := time.Parse(time.RFC3339, row.CreatedAt); err == nil {
		team.CreatedAt = t
	}
	if t, err := time.Parse(time.RFC3339, row.UpdatedAt); err == nil {
		team.UpdatedAt = t
	}
	return team
}

func sqliteTeamMemberToDomain(row *sqlitestore.TeamMember) *TeamMember {
	member := &TeamMember{
		ID:     row.ID,
		TeamID: row.TeamID,
		UserID: row.UserID,
	}
	if t, err := time.Parse(time.RFC3339, row.CreatedAt); err == nil {
		member.CreatedAt = t
	}
	return member
}
