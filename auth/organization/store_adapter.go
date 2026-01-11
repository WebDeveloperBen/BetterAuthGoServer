package organization

import (
	"context"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/db"
)

// StoreAdapter wraps db.PluginStore to provide organization-specific operations.
// It converts between plugin domain types and db package types.
type StoreAdapter struct {
	store db.PluginStore
}

// NewStoreAdapter creates a new store adapter.
func NewStoreAdapter(store db.PluginStore) *StoreAdapter {
	return &StoreAdapter{store: store}
}

// =============================================================================
// Organization operations
// =============================================================================

// CreateOrganization creates a new organization.
func (a *StoreAdapter) CreateOrganization(ctx context.Context, org *Organization) error {
	return a.store.CreateOrganization(ctx, orgToDBModel(org))
}

// GetOrganizationByID retrieves an organization by ID.
func (a *StoreAdapter) GetOrganizationByID(ctx context.Context, id string) (*Organization, error) {
	dbOrg, err := a.store.GetOrganizationByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if dbOrg == nil {
		return nil, nil
	}
	return dbOrgToModel(dbOrg), nil
}

// GetOrganizationBySlug retrieves an organization by slug.
func (a *StoreAdapter) GetOrganizationBySlug(ctx context.Context, slug string) (*Organization, error) {
	dbOrg, err := a.store.GetOrganizationBySlug(ctx, slug)
	if err != nil {
		return nil, err
	}
	if dbOrg == nil {
		return nil, nil
	}
	return dbOrgToModel(dbOrg), nil
}

// UpdateOrganization updates an organization.
func (a *StoreAdapter) UpdateOrganization(ctx context.Context, org *Organization) error {
	return a.store.UpdateOrganization(ctx, orgToDBModel(org))
}

// DeleteOrganization deletes an organization.
func (a *StoreAdapter) DeleteOrganization(ctx context.Context, id string) error {
	return a.store.DeleteOrganization(ctx, id)
}

// ListUserOrganizations lists organizations where the user is a member.
func (a *StoreAdapter) ListUserOrganizations(ctx context.Context, userID string) ([]*Organization, error) {
	dbOrgs, err := a.store.ListUserOrganizations(ctx, userID)
	if err != nil {
		return nil, err
	}
	orgs := make([]*Organization, len(dbOrgs))
	for i, dbOrg := range dbOrgs {
		orgs[i] = dbOrgToModel(dbOrg)
	}
	return orgs, nil
}

// CheckSlugExists checks if an organization slug already exists.
func (a *StoreAdapter) CheckSlugExists(ctx context.Context, slug string) (bool, error) {
	return a.store.CheckSlugExists(ctx, slug)
}

// =============================================================================
// Member operations
// =============================================================================

// CreateMember adds a member to an organization.
func (a *StoreAdapter) CreateMember(ctx context.Context, member *Member) error {
	return a.store.CreateMember(ctx, memberToDBModel(member))
}

// GetMember retrieves a member by organization ID and user ID.
func (a *StoreAdapter) GetMember(ctx context.Context, orgID, userID string) (*Member, error) {
	dbMember, err := a.store.GetMember(ctx, orgID, userID)
	if err != nil {
		return nil, err
	}
	if dbMember == nil {
		return nil, nil
	}
	return dbMemberToModel(dbMember), nil
}

// GetMemberByID retrieves a member by ID.
func (a *StoreAdapter) GetMemberByID(ctx context.Context, id string) (*Member, error) {
	dbMember, err := a.store.GetMemberByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if dbMember == nil {
		return nil, nil
	}
	return dbMemberToModel(dbMember), nil
}

// ListMembersByOrganization lists all members of an organization.
func (a *StoreAdapter) ListMembersByOrganization(ctx context.Context, orgID string) ([]*Member, error) {
	dbMembers, err := a.store.ListMembersByOrganization(ctx, orgID)
	if err != nil {
		return nil, err
	}
	members := make([]*Member, len(dbMembers))
	for i, dbMember := range dbMembers {
		members[i] = dbMemberToModel(dbMember)
	}
	return members, nil
}

// ListMembersByUser lists all memberships for a user.
func (a *StoreAdapter) ListMembersByUser(ctx context.Context, userID string) ([]*Member, error) {
	dbMembers, err := a.store.ListMembersByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	members := make([]*Member, len(dbMembers))
	for i, dbMember := range dbMembers {
		members[i] = dbMemberToModel(dbMember)
	}
	return members, nil
}

// UpdateMemberRole updates a member's role.
func (a *StoreAdapter) UpdateMemberRole(ctx context.Context, id, role string, updatedAt time.Time) error {
	return a.store.UpdateMemberRole(ctx, id, role, updatedAt)
}

// DeleteMember removes a member from an organization.
func (a *StoreAdapter) DeleteMember(ctx context.Context, orgID, userID string) error {
	return a.store.DeleteMember(ctx, orgID, userID)
}

// CountOrganizationMembers counts the members of an organization.
func (a *StoreAdapter) CountOrganizationMembers(ctx context.Context, orgID string) (int64, error) {
	return a.store.CountOrganizationMembers(ctx, orgID)
}

// GetFirstMemberByUser gets the first membership for a user.
func (a *StoreAdapter) GetFirstMemberByUser(ctx context.Context, userID string) (*Member, error) {
	dbMember, err := a.store.GetFirstMemberByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if dbMember == nil {
		return nil, nil
	}
	return dbMemberToModel(dbMember), nil
}

// =============================================================================
// Invitation operations
// =============================================================================

// CreateInvitation creates a new invitation.
func (a *StoreAdapter) CreateInvitation(ctx context.Context, inv *Invitation) error {
	return a.store.CreateInvitation(ctx, invitationToDBModel(inv))
}

// GetInvitationByID retrieves an invitation by ID.
func (a *StoreAdapter) GetInvitationByID(ctx context.Context, id string) (*Invitation, error) {
	dbInv, err := a.store.GetInvitationByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if dbInv == nil {
		return nil, nil
	}
	return dbInvitationToModel(dbInv), nil
}

// GetPendingInvitationByEmailAndOrg retrieves a pending invitation.
func (a *StoreAdapter) GetPendingInvitationByEmailAndOrg(ctx context.Context, email, orgID string) (*Invitation, error) {
	dbInv, err := a.store.GetPendingInvitationByEmailAndOrg(ctx, email, orgID)
	if err != nil {
		return nil, err
	}
	if dbInv == nil {
		return nil, nil
	}
	return dbInvitationToModel(dbInv), nil
}

// ListInvitationsByOrganization lists all invitations for an organization.
func (a *StoreAdapter) ListInvitationsByOrganization(ctx context.Context, orgID string) ([]*Invitation, error) {
	dbInvs, err := a.store.ListInvitationsByOrganization(ctx, orgID)
	if err != nil {
		return nil, err
	}
	invs := make([]*Invitation, len(dbInvs))
	for i, dbInv := range dbInvs {
		invs[i] = dbInvitationToModel(dbInv)
	}
	return invs, nil
}

// ListPendingInvitationsByEmail lists pending invitations for an email.
func (a *StoreAdapter) ListPendingInvitationsByEmail(ctx context.Context, email string) ([]*Invitation, error) {
	dbInvs, err := a.store.ListPendingInvitationsByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	invs := make([]*Invitation, len(dbInvs))
	for i, dbInv := range dbInvs {
		invs[i] = dbInvitationToModel(dbInv)
	}
	return invs, nil
}

// UpdateInvitationStatus updates an invitation's status.
func (a *StoreAdapter) UpdateInvitationStatus(ctx context.Context, id, status string) error {
	return a.store.UpdateInvitationStatus(ctx, id, status)
}

// CancelPendingInvitations cancels all pending invitations.
func (a *StoreAdapter) CancelPendingInvitations(ctx context.Context, email, orgID string) error {
	return a.store.CancelPendingInvitations(ctx, email, orgID)
}

// DeleteExpiredInvitations removes expired invitations.
func (a *StoreAdapter) DeleteExpiredInvitations(ctx context.Context) (int64, error) {
	return a.store.DeleteExpiredInvitations(ctx)
}

// =============================================================================
// Team operations
// =============================================================================

// CreateTeam creates a new team.
func (a *StoreAdapter) CreateTeam(ctx context.Context, team *Team) error {
	return a.store.CreateTeam(ctx, teamToDBModel(team))
}

// GetTeamByID retrieves a team by ID.
func (a *StoreAdapter) GetTeamByID(ctx context.Context, id string) (*Team, error) {
	dbTeam, err := a.store.GetTeamByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if dbTeam == nil {
		return nil, nil
	}
	return dbTeamToModel(dbTeam), nil
}

// ListTeamsByOrganization lists all teams for an organization.
func (a *StoreAdapter) ListTeamsByOrganization(ctx context.Context, orgID string) ([]*Team, error) {
	dbTeams, err := a.store.ListTeamsByOrganization(ctx, orgID)
	if err != nil {
		return nil, err
	}
	teams := make([]*Team, len(dbTeams))
	for i, dbTeam := range dbTeams {
		teams[i] = dbTeamToModel(dbTeam)
	}
	return teams, nil
}

// UpdateTeam updates a team.
func (a *StoreAdapter) UpdateTeam(ctx context.Context, id, name string, updatedAt time.Time) error {
	return a.store.UpdateTeam(ctx, id, name, updatedAt)
}

// DeleteTeam deletes a team.
func (a *StoreAdapter) DeleteTeam(ctx context.Context, id string) error {
	return a.store.DeleteTeam(ctx, id)
}

// =============================================================================
// Team Member operations
// =============================================================================

// CreateTeamMember adds a member to a team.
func (a *StoreAdapter) CreateTeamMember(ctx context.Context, member *TeamMember) error {
	return a.store.CreateTeamMember(ctx, teamMemberToDBModel(member))
}

// GetTeamMember retrieves a team member.
func (a *StoreAdapter) GetTeamMember(ctx context.Context, teamID, userID string) (*TeamMember, error) {
	dbMember, err := a.store.GetTeamMember(ctx, teamID, userID)
	if err != nil {
		return nil, err
	}
	if dbMember == nil {
		return nil, nil
	}
	return dbTeamMemberToModel(dbMember), nil
}

// ListTeamMembersByTeam lists all members of a team.
func (a *StoreAdapter) ListTeamMembersByTeam(ctx context.Context, teamID string) ([]*TeamMember, error) {
	dbMembers, err := a.store.ListTeamMembersByTeam(ctx, teamID)
	if err != nil {
		return nil, err
	}
	members := make([]*TeamMember, len(dbMembers))
	for i, dbMember := range dbMembers {
		members[i] = dbTeamMemberToModel(dbMember)
	}
	return members, nil
}

// ListTeamMembersByUser lists all team memberships for a user.
func (a *StoreAdapter) ListTeamMembersByUser(ctx context.Context, userID string) ([]*TeamMember, error) {
	dbMembers, err := a.store.ListTeamMembersByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	members := make([]*TeamMember, len(dbMembers))
	for i, dbMember := range dbMembers {
		members[i] = dbTeamMemberToModel(dbMember)
	}
	return members, nil
}

// DeleteTeamMember removes a member from a team.
func (a *StoreAdapter) DeleteTeamMember(ctx context.Context, teamID, userID string) error {
	return a.store.DeleteTeamMember(ctx, teamID, userID)
}

// =============================================================================
// Model converters: plugin domain types <-> db package types
// =============================================================================

func orgToDBModel(org *Organization) *db.Organization {
	return &db.Organization{
		ID:        org.ID,
		Name:      org.Name,
		Slug:      org.Slug,
		Logo:      org.Logo,
		Metadata:  org.Metadata,
		CreatedAt: org.CreatedAt,
		UpdatedAt: org.UpdatedAt,
	}
}

func dbOrgToModel(dbOrg *db.Organization) *Organization {
	return &Organization{
		ID:        dbOrg.ID,
		Name:      dbOrg.Name,
		Slug:      dbOrg.Slug,
		Logo:      dbOrg.Logo,
		Metadata:  dbOrg.Metadata,
		CreatedAt: dbOrg.CreatedAt,
		UpdatedAt: dbOrg.UpdatedAt,
	}
}

func memberToDBModel(m *Member) *db.OrgMember {
	return &db.OrgMember{
		ID:             m.ID,
		OrganizationID: m.OrganizationID,
		UserID:         m.UserID,
		Role:           m.Role,
		CreatedAt:      m.CreatedAt,
		UpdatedAt:      m.UpdatedAt,
	}
}

func dbMemberToModel(dbM *db.OrgMember) *Member {
	return &Member{
		ID:             dbM.ID,
		OrganizationID: dbM.OrganizationID,
		UserID:         dbM.UserID,
		Role:           dbM.Role,
		CreatedAt:      dbM.CreatedAt,
		UpdatedAt:      dbM.UpdatedAt,
	}
}

func invitationToDBModel(inv *Invitation) *db.OrgInvitation {
	return &db.OrgInvitation{
		ID:             inv.ID,
		Email:          inv.Email,
		OrganizationID: inv.OrganizationID,
		InviterID:      inv.InviterID,
		Role:           inv.Role,
		Status:         inv.Status,
		ExpiresAt:      inv.ExpiresAt,
		CreatedAt:      inv.CreatedAt,
	}
}

func dbInvitationToModel(dbInv *db.OrgInvitation) *Invitation {
	return &Invitation{
		ID:             dbInv.ID,
		Email:          dbInv.Email,
		OrganizationID: dbInv.OrganizationID,
		InviterID:      dbInv.InviterID,
		Role:           dbInv.Role,
		Status:         dbInv.Status,
		ExpiresAt:      dbInv.ExpiresAt,
		CreatedAt:      dbInv.CreatedAt,
	}
}

func teamToDBModel(t *Team) *db.OrgTeam {
	return &db.OrgTeam{
		ID:             t.ID,
		Name:           t.Name,
		OrganizationID: t.OrganizationID,
		CreatedAt:      t.CreatedAt,
		UpdatedAt:      t.UpdatedAt,
	}
}

func dbTeamToModel(dbT *db.OrgTeam) *Team {
	return &Team{
		ID:             dbT.ID,
		Name:           dbT.Name,
		OrganizationID: dbT.OrganizationID,
		CreatedAt:      dbT.CreatedAt,
		UpdatedAt:      dbT.UpdatedAt,
	}
}

func teamMemberToDBModel(m *TeamMember) *db.OrgTeamMember {
	return &db.OrgTeamMember{
		ID:        m.ID,
		TeamID:    m.TeamID,
		UserID:    m.UserID,
		CreatedAt: m.CreatedAt,
	}
}

func dbTeamMemberToModel(dbM *db.OrgTeamMember) *TeamMember {
	return &TeamMember{
		ID:        dbM.ID,
		TeamID:    dbM.TeamID,
		UserID:    dbM.UserID,
		CreatedAt: dbM.CreatedAt,
	}
}
