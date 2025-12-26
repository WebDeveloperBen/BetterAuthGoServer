// Package organization provides multi-tenant organization and team management.
package organization

import (
	"context"
	"net/http"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// UserProvider defines the auth operations required by the organization middleware.
// The main Auth struct implements this interface.
type UserProvider interface {
	// GetUserFromRequest retrieves the authenticated user from the request context
	GetUserFromRequest(r *http.Request) (*plugin.User, error)
}

// OrganizationProvider defines additional operations needed for organization management.
type OrganizationProvider interface {
	UserProvider

	// CreatePluginUser creates a new user (for adding members directly)
	CreatePluginUser(ctx context.Context, req plugin.CreateUserRequest) (*plugin.User, error)
}

// SessionInfoProvider defines operations to get session info from requests.
// The main Auth struct implements this interface.
type SessionInfoProvider interface {
	// GetSessionInfoFromRequest gets the session ID and user ID from the request context.
	// Returns nil if no session is present.
	GetSessionInfoFromRequest(r *http.Request) *plugin.SessionInfo
}

// OrganizationOperations defines the interface for organization operations.
// This is implemented by the Service type.
type OrganizationOperations interface {
	// Organization CRUD
	CreateOrganization(ctx context.Context, name, slug string, creatorID string, metadata map[string]any) (*Organization, error)
	GetOrganization(ctx context.Context, id string) (*Organization, error)
	GetOrganizationBySlug(ctx context.Context, slug string) (*Organization, error)
	UpdateOrganization(ctx context.Context, id string, updates map[string]any) (*Organization, error)
	DeleteOrganization(ctx context.Context, id string) error
	ListUserOrganizations(ctx context.Context, userID string) ([]*Organization, error)

	// Member management
	AddMember(ctx context.Context, organizationID, userID, role string) (*Member, error)
	RemoveMember(ctx context.Context, organizationID, userID string) error
	UpdateMemberRole(ctx context.Context, organizationID, userID, role string) (*Member, error)
	GetMember(ctx context.Context, organizationID, userID string) (*Member, error)
	ListMembers(ctx context.Context, organizationID string) ([]*Member, error)
	GetActiveMember(ctx context.Context, userID string) (*Member, error)

	// Invitations
	CreateInvitation(ctx context.Context, organizationID, email, role, inviterID string) (*Invitation, error)
	AcceptInvitation(ctx context.Context, invitationID, userID string) (*Member, error)
	RejectInvitation(ctx context.Context, invitationID, userID string) error
	CancelInvitation(ctx context.Context, invitationID, cancelledBy string) error
	ListInvitations(ctx context.Context, organizationID string) ([]*Invitation, error)
	ListUserInvitations(ctx context.Context, email string) ([]*Invitation, error)
	GetInvitation(ctx context.Context, id string) (*Invitation, error)

	// Teams (optional)
	CreateTeam(ctx context.Context, organizationID, name string) (*Team, error)
	GetTeam(ctx context.Context, teamID string) (*Team, error)
	UpdateTeam(ctx context.Context, teamID, name string) (*Team, error)
	DeleteTeam(ctx context.Context, teamID string) error
	ListTeams(ctx context.Context, organizationID string) ([]*Team, error)

	AddTeamMember(ctx context.Context, teamID, userID string) (*TeamMember, error)
	RemoveTeamMember(ctx context.Context, teamID, userID string) error
	ListTeamMembers(ctx context.Context, teamID string) ([]*TeamMember, error)

	// Session management
	SetActiveOrganization(ctx context.Context, sessionID string, organizationID *string) error
	SetActiveTeam(ctx context.Context, sessionID string, teamID *string) error
	GetActiveOrganization(ctx context.Context, sessionID string) (*string, error)
}

// Ensure Service implements OrganizationOperations
var _ OrganizationOperations = (*Service)(nil)
