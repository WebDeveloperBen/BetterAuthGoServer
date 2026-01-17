// Package db provides database storage implementations for organization management.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/organization/db/mysqlstore"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/organization/db/pgstore"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/organization/db/sqlitestore"
	coredb "github.com/webdeveloperben/BetterAuthGoServer/db"
)

// =============================================================================
// Domain types
// =============================================================================

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

// =============================================================================
// Querier interface - each dialect implements this
// =============================================================================

// Querier defines all organization database operations.
// Each dialect implements this interface, handling type conversions internally.
type Querier interface {
	// Organization operations
	CreateOrganization(ctx context.Context, org *Organization) error
	GetOrganizationByID(ctx context.Context, id string) (*Organization, error)
	GetOrganizationBySlug(ctx context.Context, slug string) (*Organization, error)
	UpdateOrganization(ctx context.Context, org *Organization) error
	DeleteOrganization(ctx context.Context, id string) error
	ListUserOrganizations(ctx context.Context, userID string) ([]*Organization, error)
	CheckSlugExists(ctx context.Context, slug string) (bool, error)

	// Member operations
	CreateMember(ctx context.Context, member *Member) error
	GetMember(ctx context.Context, orgID, userID string) (*Member, error)
	GetMemberByID(ctx context.Context, id string) (*Member, error)
	ListMembersByOrganization(ctx context.Context, orgID string) ([]*Member, error)
	ListMembersByUser(ctx context.Context, userID string) ([]*Member, error)
	UpdateMemberRole(ctx context.Context, id, role string, updatedAt time.Time) error
	DeleteMember(ctx context.Context, orgID, userID string) error
	CountOrganizationMembers(ctx context.Context, orgID string) (int64, error)
	GetFirstMemberByUser(ctx context.Context, userID string) (*Member, error)

	// Invitation operations
	CreateInvitation(ctx context.Context, inv *Invitation) error
	GetInvitationByID(ctx context.Context, id string) (*Invitation, error)
	GetPendingInvitationByEmailAndOrg(ctx context.Context, email, orgID string) (*Invitation, error)
	ListInvitationsByOrganization(ctx context.Context, orgID string) ([]*Invitation, error)
	ListPendingInvitationsByEmail(ctx context.Context, email string) ([]*Invitation, error)
	UpdateInvitationStatus(ctx context.Context, id, status string) error
	CancelPendingInvitations(ctx context.Context, email, orgID string) error
	DeleteExpiredInvitations(ctx context.Context) (int64, error)

	// Team operations
	CreateTeam(ctx context.Context, team *Team) error
	GetTeamByID(ctx context.Context, id string) (*Team, error)
	ListTeamsByOrganization(ctx context.Context, orgID string) ([]*Team, error)
	UpdateTeam(ctx context.Context, id, name string, updatedAt time.Time) error
	DeleteTeam(ctx context.Context, id string) error

	// Team member operations
	CreateTeamMember(ctx context.Context, member *TeamMember) error
	GetTeamMember(ctx context.Context, teamID, userID string) (*TeamMember, error)
	ListTeamMembersByTeam(ctx context.Context, teamID string) ([]*TeamMember, error)
	ListTeamMembersByUser(ctx context.Context, userID string) ([]*TeamMember, error)
	DeleteTeamMember(ctx context.Context, teamID, userID string) error
}

// =============================================================================
// Store - delegates to dialect-specific Querier
// =============================================================================

// Store wraps the sqlc-generated queries for organization operations.
type Store struct {
	q Querier
}

// New creates a new Store for organization operations.
func New(db coredb.DBTX, dialect coredb.Dialect) (*Store, error) {
	var q Querier

	switch dialect {
	case coredb.DialectPostgres:
		q = newPgAdapter(db)
	case coredb.DialectMySQL:
		q = newMysqlAdapter(db)
	case coredb.DialectSQLite:
		q = newSqliteAdapter(db)
	default:
		return nil, fmt.Errorf("unsupported dialect: %s", dialect)
	}

	return &Store{q: q}, nil
}

// =============================================================================
// Store delegation methods
// =============================================================================

// Organization operations

func (s *Store) CreateOrganization(ctx context.Context, org *Organization) error {
	return s.q.CreateOrganization(ctx, org)
}

func (s *Store) GetOrganizationByID(ctx context.Context, id string) (*Organization, error) {
	return s.q.GetOrganizationByID(ctx, id)
}

func (s *Store) GetOrganizationBySlug(ctx context.Context, slug string) (*Organization, error) {
	return s.q.GetOrganizationBySlug(ctx, slug)
}

func (s *Store) UpdateOrganization(ctx context.Context, org *Organization) error {
	return s.q.UpdateOrganization(ctx, org)
}

func (s *Store) DeleteOrganization(ctx context.Context, id string) error {
	return s.q.DeleteOrganization(ctx, id)
}

func (s *Store) ListUserOrganizations(ctx context.Context, userID string) ([]*Organization, error) {
	return s.q.ListUserOrganizations(ctx, userID)
}

func (s *Store) CheckSlugExists(ctx context.Context, slug string) (bool, error) {
	return s.q.CheckSlugExists(ctx, slug)
}

// Member operations

func (s *Store) CreateMember(ctx context.Context, member *Member) error {
	return s.q.CreateMember(ctx, member)
}

func (s *Store) GetMember(ctx context.Context, orgID, userID string) (*Member, error) {
	return s.q.GetMember(ctx, orgID, userID)
}

func (s *Store) GetMemberByID(ctx context.Context, id string) (*Member, error) {
	return s.q.GetMemberByID(ctx, id)
}

func (s *Store) ListMembersByOrganization(ctx context.Context, orgID string) ([]*Member, error) {
	return s.q.ListMembersByOrganization(ctx, orgID)
}

func (s *Store) ListMembersByUser(ctx context.Context, userID string) ([]*Member, error) {
	return s.q.ListMembersByUser(ctx, userID)
}

func (s *Store) UpdateMemberRole(ctx context.Context, id, role string, updatedAt time.Time) error {
	return s.q.UpdateMemberRole(ctx, id, role, updatedAt)
}

func (s *Store) DeleteMember(ctx context.Context, orgID, userID string) error {
	return s.q.DeleteMember(ctx, orgID, userID)
}

func (s *Store) CountOrganizationMembers(ctx context.Context, orgID string) (int64, error) {
	return s.q.CountOrganizationMembers(ctx, orgID)
}

func (s *Store) GetFirstMemberByUser(ctx context.Context, userID string) (*Member, error) {
	return s.q.GetFirstMemberByUser(ctx, userID)
}

// Invitation operations

func (s *Store) CreateInvitation(ctx context.Context, inv *Invitation) error {
	return s.q.CreateInvitation(ctx, inv)
}

func (s *Store) GetInvitationByID(ctx context.Context, id string) (*Invitation, error) {
	return s.q.GetInvitationByID(ctx, id)
}

func (s *Store) GetPendingInvitationByEmailAndOrg(ctx context.Context, email, orgID string) (*Invitation, error) {
	return s.q.GetPendingInvitationByEmailAndOrg(ctx, email, orgID)
}

func (s *Store) ListInvitationsByOrganization(ctx context.Context, orgID string) ([]*Invitation, error) {
	return s.q.ListInvitationsByOrganization(ctx, orgID)
}

func (s *Store) ListPendingInvitationsByEmail(ctx context.Context, email string) ([]*Invitation, error) {
	return s.q.ListPendingInvitationsByEmail(ctx, email)
}

func (s *Store) UpdateInvitationStatus(ctx context.Context, id, status string) error {
	return s.q.UpdateInvitationStatus(ctx, id, status)
}

func (s *Store) CancelPendingInvitations(ctx context.Context, email, orgID string) error {
	return s.q.CancelPendingInvitations(ctx, email, orgID)
}

func (s *Store) DeleteExpiredInvitations(ctx context.Context) (int64, error) {
	return s.q.DeleteExpiredInvitations(ctx)
}

// Team operations

func (s *Store) CreateTeam(ctx context.Context, team *Team) error {
	return s.q.CreateTeam(ctx, team)
}

func (s *Store) GetTeamByID(ctx context.Context, id string) (*Team, error) {
	return s.q.GetTeamByID(ctx, id)
}

func (s *Store) ListTeamsByOrganization(ctx context.Context, orgID string) ([]*Team, error) {
	return s.q.ListTeamsByOrganization(ctx, orgID)
}

func (s *Store) UpdateTeam(ctx context.Context, id, name string, updatedAt time.Time) error {
	return s.q.UpdateTeam(ctx, id, name, updatedAt)
}

func (s *Store) DeleteTeam(ctx context.Context, id string) error {
	return s.q.DeleteTeam(ctx, id)
}

// Team member operations

func (s *Store) CreateTeamMember(ctx context.Context, member *TeamMember) error {
	return s.q.CreateTeamMember(ctx, member)
}

func (s *Store) GetTeamMember(ctx context.Context, teamID, userID string) (*TeamMember, error) {
	return s.q.GetTeamMember(ctx, teamID, userID)
}

func (s *Store) ListTeamMembersByTeam(ctx context.Context, teamID string) ([]*TeamMember, error) {
	return s.q.ListTeamMembersByTeam(ctx, teamID)
}

func (s *Store) ListTeamMembersByUser(ctx context.Context, userID string) ([]*TeamMember, error) {
	return s.q.ListTeamMembersByUser(ctx, userID)
}

func (s *Store) DeleteTeamMember(ctx context.Context, teamID, userID string) error {
	return s.q.DeleteTeamMember(ctx, teamID, userID)
}

// =============================================================================
// PostgreSQL adapter
// =============================================================================

type pgAdapter struct {
	q *pgstore.Queries
}

func newPgAdapter(db coredb.DBTX) *pgAdapter {
	return &pgAdapter{q: pgstore.New(db)}
}

// Organization operations

func (a *pgAdapter) CreateOrganization(ctx context.Context, org *Organization) error {
	return a.q.CreateOrganization(ctx, pgstore.CreateOrganizationParams{
		ID:        org.ID,
		Name:      org.Name,
		Slug:      org.Slug,
		Logo:      toNullString(org.Logo),
		Metadata:  toNullString(org.Metadata),
		CreatedAt: org.CreatedAt,
		UpdatedAt: org.UpdatedAt,
	})
}

func (a *pgAdapter) GetOrganizationByID(ctx context.Context, id string) (*Organization, error) {
	row, err := a.q.GetOrganizationByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return pgOrgToDomain(&row), nil
}

func (a *pgAdapter) GetOrganizationBySlug(ctx context.Context, slug string) (*Organization, error) {
	row, err := a.q.GetOrganizationBySlug(ctx, slug)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return pgOrgToDomain(&row), nil
}

func (a *pgAdapter) UpdateOrganization(ctx context.Context, org *Organization) error {
	return a.q.UpdateOrganization(ctx, pgstore.UpdateOrganizationParams{
		ID:        org.ID,
		Name:      org.Name,
		Slug:      org.Slug,
		Logo:      toNullString(org.Logo),
		Metadata:  toNullString(org.Metadata),
		UpdatedAt: org.UpdatedAt,
	})
}

func (a *pgAdapter) DeleteOrganization(ctx context.Context, id string) error {
	return a.q.DeleteOrganization(ctx, id)
}

func (a *pgAdapter) ListUserOrganizations(ctx context.Context, userID string) ([]*Organization, error) {
	rows, err := a.q.ListUserOrganizations(ctx, userID)
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

func (a *pgAdapter) CheckSlugExists(ctx context.Context, slug string) (bool, error) {
	return a.q.CheckSlugExists(ctx, slug)
}

// Member operations

func (a *pgAdapter) CreateMember(ctx context.Context, member *Member) error {
	return a.q.CreateMember(ctx, pgstore.CreateMemberParams{
		ID:             member.ID,
		OrganizationID: member.OrganizationID,
		UserID:         member.UserID,
		Role:           member.Role,
		CreatedAt:      member.CreatedAt,
		UpdatedAt:      member.UpdatedAt,
	})
}

func (a *pgAdapter) GetMember(ctx context.Context, orgID, userID string) (*Member, error) {
	row, err := a.q.GetMember(ctx, pgstore.GetMemberParams{
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

func (a *pgAdapter) GetMemberByID(ctx context.Context, id string) (*Member, error) {
	row, err := a.q.GetMemberByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return pgMemberToDomain(&row), nil
}

func (a *pgAdapter) ListMembersByOrganization(ctx context.Context, orgID string) ([]*Member, error) {
	rows, err := a.q.ListMembersByOrganization(ctx, orgID)
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

func (a *pgAdapter) ListMembersByUser(ctx context.Context, userID string) ([]*Member, error) {
	rows, err := a.q.ListMembersByUser(ctx, userID)
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

func (a *pgAdapter) UpdateMemberRole(ctx context.Context, id, role string, updatedAt time.Time) error {
	return a.q.UpdateMemberRole(ctx, pgstore.UpdateMemberRoleParams{
		ID:        id,
		Role:      role,
		UpdatedAt: updatedAt,
	})
}

func (a *pgAdapter) DeleteMember(ctx context.Context, orgID, userID string) error {
	return a.q.DeleteMember(ctx, pgstore.DeleteMemberParams{
		OrganizationID: orgID,
		UserID:         userID,
	})
}

func (a *pgAdapter) CountOrganizationMembers(ctx context.Context, orgID string) (int64, error) {
	return a.q.CountOrganizationMembers(ctx, orgID)
}

func (a *pgAdapter) GetFirstMemberByUser(ctx context.Context, userID string) (*Member, error) {
	row, err := a.q.GetFirstMemberByUser(ctx, userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return pgMemberToDomain(&row), nil
}

// Invitation operations

func (a *pgAdapter) CreateInvitation(ctx context.Context, inv *Invitation) error {
	return a.q.CreateInvitation(ctx, pgstore.CreateInvitationParams{
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

func (a *pgAdapter) GetInvitationByID(ctx context.Context, id string) (*Invitation, error) {
	row, err := a.q.GetInvitationByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return pgInvitationToDomain(&row), nil
}

func (a *pgAdapter) GetPendingInvitationByEmailAndOrg(ctx context.Context, email, orgID string) (*Invitation, error) {
	row, err := a.q.GetInvitationByEmailAndOrg(ctx, pgstore.GetInvitationByEmailAndOrgParams{
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

func (a *pgAdapter) ListInvitationsByOrganization(ctx context.Context, orgID string) ([]*Invitation, error) {
	rows, err := a.q.ListInvitationsByOrganization(ctx, orgID)
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

func (a *pgAdapter) ListPendingInvitationsByEmail(ctx context.Context, email string) ([]*Invitation, error) {
	rows, err := a.q.ListInvitationsByEmail(ctx, email)
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

func (a *pgAdapter) UpdateInvitationStatus(ctx context.Context, id, status string) error {
	return a.q.UpdateInvitationStatus(ctx, pgstore.UpdateInvitationStatusParams{
		ID:     id,
		Status: status,
	})
}

func (a *pgAdapter) CancelPendingInvitations(ctx context.Context, email, orgID string) error {
	return a.q.CancelPendingInvitations(ctx, pgstore.CancelPendingInvitationsParams{
		Email:          email,
		OrganizationID: orgID,
	})
}

func (a *pgAdapter) DeleteExpiredInvitations(ctx context.Context) (int64, error) {
	return a.q.DeleteExpiredInvitations(ctx)
}

// Team operations

func (a *pgAdapter) CreateTeam(ctx context.Context, team *Team) error {
	return a.q.CreateTeam(ctx, pgstore.CreateTeamParams{
		ID:             team.ID,
		Name:           team.Name,
		OrganizationID: team.OrganizationID,
		CreatedAt:      team.CreatedAt,
		UpdatedAt:      team.UpdatedAt,
	})
}

func (a *pgAdapter) GetTeamByID(ctx context.Context, id string) (*Team, error) {
	row, err := a.q.GetTeamByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return pgTeamToDomain(&row), nil
}

func (a *pgAdapter) ListTeamsByOrganization(ctx context.Context, orgID string) ([]*Team, error) {
	rows, err := a.q.ListTeamsByOrganization(ctx, orgID)
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

func (a *pgAdapter) UpdateTeam(ctx context.Context, id, name string, updatedAt time.Time) error {
	return a.q.UpdateTeam(ctx, pgstore.UpdateTeamParams{
		ID:        id,
		Name:      name,
		UpdatedAt: updatedAt,
	})
}

func (a *pgAdapter) DeleteTeam(ctx context.Context, id string) error {
	return a.q.DeleteTeam(ctx, id)
}

// Team member operations

func (a *pgAdapter) CreateTeamMember(ctx context.Context, member *TeamMember) error {
	return a.q.CreateTeamMember(ctx, pgstore.CreateTeamMemberParams{
		ID:        member.ID,
		TeamID:    member.TeamID,
		UserID:    member.UserID,
		CreatedAt: member.CreatedAt,
	})
}

func (a *pgAdapter) GetTeamMember(ctx context.Context, teamID, userID string) (*TeamMember, error) {
	row, err := a.q.GetTeamMember(ctx, pgstore.GetTeamMemberParams{
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

func (a *pgAdapter) ListTeamMembersByTeam(ctx context.Context, teamID string) ([]*TeamMember, error) {
	rows, err := a.q.ListTeamMembersByTeam(ctx, teamID)
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

func (a *pgAdapter) ListTeamMembersByUser(ctx context.Context, userID string) ([]*TeamMember, error) {
	rows, err := a.q.ListTeamMembersByUser(ctx, userID)
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

func (a *pgAdapter) DeleteTeamMember(ctx context.Context, teamID, userID string) error {
	return a.q.DeleteTeamMember(ctx, pgstore.DeleteTeamMemberParams{
		TeamID: teamID,
		UserID: userID,
	})
}

var _ Querier = (*pgAdapter)(nil)

// =============================================================================
// MySQL adapter
// =============================================================================

type mysqlAdapter struct {
	q *mysqlstore.Queries
}

func newMysqlAdapter(db coredb.DBTX) *mysqlAdapter {
	return &mysqlAdapter{q: mysqlstore.New(db)}
}

// Organization operations

func (a *mysqlAdapter) CreateOrganization(ctx context.Context, org *Organization) error {
	return a.q.CreateOrganization(ctx, mysqlstore.CreateOrganizationParams{
		ID:        org.ID,
		Name:      org.Name,
		Slug:      org.Slug,
		Logo:      toNullString(org.Logo),
		Metadata:  toNullString(org.Metadata),
		CreatedAt: org.CreatedAt,
		UpdatedAt: org.UpdatedAt,
	})
}

func (a *mysqlAdapter) GetOrganizationByID(ctx context.Context, id string) (*Organization, error) {
	row, err := a.q.GetOrganizationByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return mysqlOrgToDomain(&row), nil
}

func (a *mysqlAdapter) GetOrganizationBySlug(ctx context.Context, slug string) (*Organization, error) {
	row, err := a.q.GetOrganizationBySlug(ctx, slug)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return mysqlOrgToDomain(&row), nil
}

func (a *mysqlAdapter) UpdateOrganization(ctx context.Context, org *Organization) error {
	return a.q.UpdateOrganization(ctx, mysqlstore.UpdateOrganizationParams{
		ID:        org.ID,
		Name:      org.Name,
		Slug:      org.Slug,
		Logo:      toNullString(org.Logo),
		Metadata:  toNullString(org.Metadata),
		UpdatedAt: org.UpdatedAt,
	})
}

func (a *mysqlAdapter) DeleteOrganization(ctx context.Context, id string) error {
	return a.q.DeleteOrganization(ctx, id)
}

func (a *mysqlAdapter) ListUserOrganizations(ctx context.Context, userID string) ([]*Organization, error) {
	rows, err := a.q.ListUserOrganizations(ctx, userID)
	if err != nil {
		return nil, err
	}
	orgs := make([]*Organization, len(rows))
	for i, row := range rows {
		r := row
		orgs[i] = mysqlOrgToDomain(&r)
	}
	return orgs, nil
}

func (a *mysqlAdapter) CheckSlugExists(ctx context.Context, slug string) (bool, error) {
	return a.q.CheckSlugExists(ctx, slug)
}

// Member operations

func (a *mysqlAdapter) CreateMember(ctx context.Context, member *Member) error {
	return a.q.CreateMember(ctx, mysqlstore.CreateMemberParams{
		ID:             member.ID,
		OrganizationID: member.OrganizationID,
		UserID:         member.UserID,
		Role:           member.Role,
		CreatedAt:      member.CreatedAt,
		UpdatedAt:      member.UpdatedAt,
	})
}

func (a *mysqlAdapter) GetMember(ctx context.Context, orgID, userID string) (*Member, error) {
	row, err := a.q.GetMember(ctx, mysqlstore.GetMemberParams{
		OrganizationID: orgID,
		UserID:         userID,
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return mysqlMemberToDomain(&row), nil
}

func (a *mysqlAdapter) GetMemberByID(ctx context.Context, id string) (*Member, error) {
	row, err := a.q.GetMemberByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return mysqlMemberToDomain(&row), nil
}

func (a *mysqlAdapter) ListMembersByOrganization(ctx context.Context, orgID string) ([]*Member, error) {
	rows, err := a.q.ListMembersByOrganization(ctx, orgID)
	if err != nil {
		return nil, err
	}
	members := make([]*Member, len(rows))
	for i, row := range rows {
		r := row
		members[i] = mysqlMemberToDomain(&r)
	}
	return members, nil
}

func (a *mysqlAdapter) ListMembersByUser(ctx context.Context, userID string) ([]*Member, error) {
	rows, err := a.q.ListMembersByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	members := make([]*Member, len(rows))
	for i, row := range rows {
		r := row
		members[i] = mysqlMemberToDomain(&r)
	}
	return members, nil
}

func (a *mysqlAdapter) UpdateMemberRole(ctx context.Context, id, role string, updatedAt time.Time) error {
	return a.q.UpdateMemberRole(ctx, mysqlstore.UpdateMemberRoleParams{
		ID:        id,
		Role:      role,
		UpdatedAt: updatedAt,
	})
}

func (a *mysqlAdapter) DeleteMember(ctx context.Context, orgID, userID string) error {
	return a.q.DeleteMember(ctx, mysqlstore.DeleteMemberParams{
		OrganizationID: orgID,
		UserID:         userID,
	})
}

func (a *mysqlAdapter) CountOrganizationMembers(ctx context.Context, orgID string) (int64, error) {
	return a.q.CountOrganizationMembers(ctx, orgID)
}

func (a *mysqlAdapter) GetFirstMemberByUser(ctx context.Context, userID string) (*Member, error) {
	row, err := a.q.GetFirstMemberByUser(ctx, userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return mysqlMemberToDomain(&row), nil
}

// Invitation operations

func (a *mysqlAdapter) CreateInvitation(ctx context.Context, inv *Invitation) error {
	return a.q.CreateInvitation(ctx, mysqlstore.CreateInvitationParams{
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

func (a *mysqlAdapter) GetInvitationByID(ctx context.Context, id string) (*Invitation, error) {
	row, err := a.q.GetInvitationByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return mysqlInvitationToDomain(&row), nil
}

func (a *mysqlAdapter) GetPendingInvitationByEmailAndOrg(ctx context.Context, email, orgID string) (*Invitation, error) {
	row, err := a.q.GetInvitationByEmailAndOrg(ctx, mysqlstore.GetInvitationByEmailAndOrgParams{
		Email:          email,
		OrganizationID: orgID,
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return mysqlInvitationToDomain(&row), nil
}

func (a *mysqlAdapter) ListInvitationsByOrganization(ctx context.Context, orgID string) ([]*Invitation, error) {
	rows, err := a.q.ListInvitationsByOrganization(ctx, orgID)
	if err != nil {
		return nil, err
	}
	invs := make([]*Invitation, len(rows))
	for i, row := range rows {
		r := row
		invs[i] = mysqlInvitationToDomain(&r)
	}
	return invs, nil
}

func (a *mysqlAdapter) ListPendingInvitationsByEmail(ctx context.Context, email string) ([]*Invitation, error) {
	rows, err := a.q.ListInvitationsByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	invs := make([]*Invitation, len(rows))
	for i, row := range rows {
		r := row
		invs[i] = mysqlInvitationToDomain(&r)
	}
	return invs, nil
}

func (a *mysqlAdapter) UpdateInvitationStatus(ctx context.Context, id, status string) error {
	return a.q.UpdateInvitationStatus(ctx, mysqlstore.UpdateInvitationStatusParams{
		ID:     id,
		Status: status,
	})
}

func (a *mysqlAdapter) CancelPendingInvitations(ctx context.Context, email, orgID string) error {
	return a.q.CancelPendingInvitations(ctx, mysqlstore.CancelPendingInvitationsParams{
		Email:          email,
		OrganizationID: orgID,
	})
}

func (a *mysqlAdapter) DeleteExpiredInvitations(ctx context.Context) (int64, error) {
	return a.q.DeleteExpiredInvitations(ctx)
}

// Team operations

func (a *mysqlAdapter) CreateTeam(ctx context.Context, team *Team) error {
	return a.q.CreateTeam(ctx, mysqlstore.CreateTeamParams{
		ID:             team.ID,
		Name:           team.Name,
		OrganizationID: team.OrganizationID,
		CreatedAt:      team.CreatedAt,
		UpdatedAt:      team.UpdatedAt,
	})
}

func (a *mysqlAdapter) GetTeamByID(ctx context.Context, id string) (*Team, error) {
	row, err := a.q.GetTeamByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return mysqlTeamToDomain(&row), nil
}

func (a *mysqlAdapter) ListTeamsByOrganization(ctx context.Context, orgID string) ([]*Team, error) {
	rows, err := a.q.ListTeamsByOrganization(ctx, orgID)
	if err != nil {
		return nil, err
	}
	teams := make([]*Team, len(rows))
	for i, row := range rows {
		r := row
		teams[i] = mysqlTeamToDomain(&r)
	}
	return teams, nil
}

func (a *mysqlAdapter) UpdateTeam(ctx context.Context, id, name string, updatedAt time.Time) error {
	return a.q.UpdateTeam(ctx, mysqlstore.UpdateTeamParams{
		ID:        id,
		Name:      name,
		UpdatedAt: updatedAt,
	})
}

func (a *mysqlAdapter) DeleteTeam(ctx context.Context, id string) error {
	return a.q.DeleteTeam(ctx, id)
}

// Team member operations

func (a *mysqlAdapter) CreateTeamMember(ctx context.Context, member *TeamMember) error {
	return a.q.CreateTeamMember(ctx, mysqlstore.CreateTeamMemberParams{
		ID:        member.ID,
		TeamID:    member.TeamID,
		UserID:    member.UserID,
		CreatedAt: member.CreatedAt,
	})
}

func (a *mysqlAdapter) GetTeamMember(ctx context.Context, teamID, userID string) (*TeamMember, error) {
	row, err := a.q.GetTeamMember(ctx, mysqlstore.GetTeamMemberParams{
		TeamID: teamID,
		UserID: userID,
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return mysqlTeamMemberToDomain(&row), nil
}

func (a *mysqlAdapter) ListTeamMembersByTeam(ctx context.Context, teamID string) ([]*TeamMember, error) {
	rows, err := a.q.ListTeamMembersByTeam(ctx, teamID)
	if err != nil {
		return nil, err
	}
	members := make([]*TeamMember, len(rows))
	for i, row := range rows {
		r := row
		members[i] = mysqlTeamMemberToDomain(&r)
	}
	return members, nil
}

func (a *mysqlAdapter) ListTeamMembersByUser(ctx context.Context, userID string) ([]*TeamMember, error) {
	rows, err := a.q.ListTeamMembersByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	members := make([]*TeamMember, len(rows))
	for i, row := range rows {
		r := row
		members[i] = mysqlTeamMemberToDomain(&r)
	}
	return members, nil
}

func (a *mysqlAdapter) DeleteTeamMember(ctx context.Context, teamID, userID string) error {
	return a.q.DeleteTeamMember(ctx, mysqlstore.DeleteTeamMemberParams{
		TeamID: teamID,
		UserID: userID,
	})
}

var _ Querier = (*mysqlAdapter)(nil)

// =============================================================================
// SQLite adapter
// =============================================================================

type sqliteAdapter struct {
	q *sqlitestore.Queries
}

func newSqliteAdapter(db coredb.DBTX) *sqliteAdapter {
	return &sqliteAdapter{q: sqlitestore.New(db)}
}

// Organization operations

func (a *sqliteAdapter) CreateOrganization(ctx context.Context, org *Organization) error {
	return a.q.CreateOrganization(ctx, sqlitestore.CreateOrganizationParams{
		ID:        org.ID,
		Name:      org.Name,
		Slug:      org.Slug,
		Logo:      toNullString(org.Logo),
		Metadata:  toNullString(org.Metadata),
		CreatedAt: org.CreatedAt.Format(time.RFC3339),
		UpdatedAt: org.UpdatedAt.Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) GetOrganizationByID(ctx context.Context, id string) (*Organization, error) {
	row, err := a.q.GetOrganizationByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteOrgToDomain(&row), nil
}

func (a *sqliteAdapter) GetOrganizationBySlug(ctx context.Context, slug string) (*Organization, error) {
	row, err := a.q.GetOrganizationBySlug(ctx, slug)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteOrgToDomain(&row), nil
}

func (a *sqliteAdapter) UpdateOrganization(ctx context.Context, org *Organization) error {
	return a.q.UpdateOrganization(ctx, sqlitestore.UpdateOrganizationParams{
		ID:        org.ID,
		Name:      org.Name,
		Slug:      org.Slug,
		Logo:      toNullString(org.Logo),
		Metadata:  toNullString(org.Metadata),
		UpdatedAt: org.UpdatedAt.Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) DeleteOrganization(ctx context.Context, id string) error {
	return a.q.DeleteOrganization(ctx, id)
}

func (a *sqliteAdapter) ListUserOrganizations(ctx context.Context, userID string) ([]*Organization, error) {
	rows, err := a.q.ListUserOrganizations(ctx, userID)
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

func (a *sqliteAdapter) CheckSlugExists(ctx context.Context, slug string) (bool, error) {
	return a.q.CheckSlugExists(ctx, slug)
}

// Member operations

func (a *sqliteAdapter) CreateMember(ctx context.Context, member *Member) error {
	return a.q.CreateMember(ctx, sqlitestore.CreateMemberParams{
		ID:             member.ID,
		OrganizationID: member.OrganizationID,
		UserID:         member.UserID,
		Role:           member.Role,
		CreatedAt:      member.CreatedAt.Format(time.RFC3339),
		UpdatedAt:      member.UpdatedAt.Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) GetMember(ctx context.Context, orgID, userID string) (*Member, error) {
	row, err := a.q.GetMember(ctx, sqlitestore.GetMemberParams{
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

func (a *sqliteAdapter) GetMemberByID(ctx context.Context, id string) (*Member, error) {
	row, err := a.q.GetMemberByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteMemberToDomain(&row), nil
}

func (a *sqliteAdapter) ListMembersByOrganization(ctx context.Context, orgID string) ([]*Member, error) {
	rows, err := a.q.ListMembersByOrganization(ctx, orgID)
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

func (a *sqliteAdapter) ListMembersByUser(ctx context.Context, userID string) ([]*Member, error) {
	rows, err := a.q.ListMembersByUser(ctx, userID)
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

func (a *sqliteAdapter) UpdateMemberRole(ctx context.Context, id, role string, updatedAt time.Time) error {
	return a.q.UpdateMemberRole(ctx, sqlitestore.UpdateMemberRoleParams{
		ID:        id,
		Role:      role,
		UpdatedAt: updatedAt.Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) DeleteMember(ctx context.Context, orgID, userID string) error {
	return a.q.DeleteMember(ctx, sqlitestore.DeleteMemberParams{
		OrganizationID: orgID,
		UserID:         userID,
	})
}

func (a *sqliteAdapter) CountOrganizationMembers(ctx context.Context, orgID string) (int64, error) {
	return a.q.CountOrganizationMembers(ctx, orgID)
}

func (a *sqliteAdapter) GetFirstMemberByUser(ctx context.Context, userID string) (*Member, error) {
	row, err := a.q.GetFirstMemberByUser(ctx, userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteMemberToDomain(&row), nil
}

// Invitation operations

func (a *sqliteAdapter) CreateInvitation(ctx context.Context, inv *Invitation) error {
	return a.q.CreateInvitation(ctx, sqlitestore.CreateInvitationParams{
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

func (a *sqliteAdapter) GetInvitationByID(ctx context.Context, id string) (*Invitation, error) {
	row, err := a.q.GetInvitationByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteInvitationToDomain(&row), nil
}

func (a *sqliteAdapter) GetPendingInvitationByEmailAndOrg(ctx context.Context, email, orgID string) (*Invitation, error) {
	row, err := a.q.GetInvitationByEmailAndOrg(ctx, sqlitestore.GetInvitationByEmailAndOrgParams{
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

func (a *sqliteAdapter) ListInvitationsByOrganization(ctx context.Context, orgID string) ([]*Invitation, error) {
	rows, err := a.q.ListInvitationsByOrganization(ctx, orgID)
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

func (a *sqliteAdapter) ListPendingInvitationsByEmail(ctx context.Context, email string) ([]*Invitation, error) {
	rows, err := a.q.ListInvitationsByEmail(ctx, email)
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

func (a *sqliteAdapter) UpdateInvitationStatus(ctx context.Context, id, status string) error {
	return a.q.UpdateInvitationStatus(ctx, sqlitestore.UpdateInvitationStatusParams{
		ID:     id,
		Status: status,
	})
}

func (a *sqliteAdapter) CancelPendingInvitations(ctx context.Context, email, orgID string) error {
	return a.q.CancelPendingInvitations(ctx, sqlitestore.CancelPendingInvitationsParams{
		Email:          email,
		OrganizationID: orgID,
	})
}

func (a *sqliteAdapter) DeleteExpiredInvitations(ctx context.Context) (int64, error) {
	return a.q.DeleteExpiredInvitations(ctx)
}

// Team operations

func (a *sqliteAdapter) CreateTeam(ctx context.Context, team *Team) error {
	return a.q.CreateTeam(ctx, sqlitestore.CreateTeamParams{
		ID:             team.ID,
		Name:           team.Name,
		OrganizationID: team.OrganizationID,
		CreatedAt:      team.CreatedAt.Format(time.RFC3339),
		UpdatedAt:      team.UpdatedAt.Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) GetTeamByID(ctx context.Context, id string) (*Team, error) {
	row, err := a.q.GetTeamByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteTeamToDomain(&row), nil
}

func (a *sqliteAdapter) ListTeamsByOrganization(ctx context.Context, orgID string) ([]*Team, error) {
	rows, err := a.q.ListTeamsByOrganization(ctx, orgID)
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

func (a *sqliteAdapter) UpdateTeam(ctx context.Context, id, name string, updatedAt time.Time) error {
	return a.q.UpdateTeam(ctx, sqlitestore.UpdateTeamParams{
		ID:        id,
		Name:      name,
		UpdatedAt: updatedAt.Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) DeleteTeam(ctx context.Context, id string) error {
	return a.q.DeleteTeam(ctx, id)
}

// Team member operations

func (a *sqliteAdapter) CreateTeamMember(ctx context.Context, member *TeamMember) error {
	return a.q.CreateTeamMember(ctx, sqlitestore.CreateTeamMemberParams{
		ID:        member.ID,
		TeamID:    member.TeamID,
		UserID:    member.UserID,
		CreatedAt: member.CreatedAt.Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) GetTeamMember(ctx context.Context, teamID, userID string) (*TeamMember, error) {
	row, err := a.q.GetTeamMember(ctx, sqlitestore.GetTeamMemberParams{
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

func (a *sqliteAdapter) ListTeamMembersByTeam(ctx context.Context, teamID string) ([]*TeamMember, error) {
	rows, err := a.q.ListTeamMembersByTeam(ctx, teamID)
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

func (a *sqliteAdapter) ListTeamMembersByUser(ctx context.Context, userID string) ([]*TeamMember, error) {
	rows, err := a.q.ListTeamMembersByUser(ctx, userID)
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

func (a *sqliteAdapter) DeleteTeamMember(ctx context.Context, teamID, userID string) error {
	return a.q.DeleteTeamMember(ctx, sqlitestore.DeleteTeamMemberParams{
		TeamID: teamID,
		UserID: userID,
	})
}

var _ Querier = (*sqliteAdapter)(nil)

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

// =============================================================================
// PostgreSQL domain converters
// =============================================================================

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

// =============================================================================
// MySQL domain converters
// =============================================================================

func mysqlOrgToDomain(row *mysqlstore.Organization) *Organization {
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

func mysqlMemberToDomain(row *mysqlstore.Member) *Member {
	return &Member{
		ID:             row.ID,
		OrganizationID: row.OrganizationID,
		UserID:         row.UserID,
		Role:           row.Role,
		CreatedAt:      row.CreatedAt,
		UpdatedAt:      row.UpdatedAt,
	}
}

func mysqlInvitationToDomain(row *mysqlstore.Invitation) *Invitation {
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

func mysqlTeamToDomain(row *mysqlstore.Team) *Team {
	return &Team{
		ID:             row.ID,
		Name:           row.Name,
		OrganizationID: row.OrganizationID,
		CreatedAt:      row.CreatedAt,
		UpdatedAt:      row.UpdatedAt,
	}
}

func mysqlTeamMemberToDomain(row *mysqlstore.TeamMember) *TeamMember {
	return &TeamMember{
		ID:        row.ID,
		TeamID:    row.TeamID,
		UserID:    row.UserID,
		CreatedAt: row.CreatedAt,
	}
}

// =============================================================================
// SQLite domain converters
// =============================================================================

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
