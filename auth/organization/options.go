package organization

import (
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/organization/access"
)

// Config holds the configuration for the organization plugin.
type Config struct {
	// Access control
	AccessControl *access.AccessControl
	Roles         map[string]*access.Role

	// Organization settings
	AllowUserToCreateOrganization func(userID string) bool
	OrganizationLimit             func(userID string) int
	CreatorRole                   string // "owner" or "admin"

	// Member settings
	MembershipLimit int

	// Invitation settings
	SendInvitationEmail                func(invitation *Invitation, organization *Organization) error
	InvitationExpiresIn                time.Duration
	CancelPendingInvitationsOnReInvite bool

	// Team settings (optional)
	Teams TeamsConfig

	// Hooks
	OrganizationHooks OrganizationHooks
}

// TeamsConfig holds team-related configuration
type TeamsConfig struct {
	Enabled               bool
	MaximumTeams          func(orgID string) int
	MaximumMembersPerTeam func(teamID string) int
	AllowRemovingAllTeams bool
}

// OrganizationHooks contains lifecycle hooks for organizations
type OrganizationHooks struct {
	BeforeCreateOrganization func(org *Organization, userID string) error
	AfterCreateOrganization  func(org *Organization, member *Member, userID string) error

	BeforeUpdateOrganization func(org *Organization, userID string) error
	AfterUpdateOrganization  func(org *Organization, userID string) error

	BeforeDeleteOrganization func(org *Organization, userID string) error
	AfterDeleteOrganization  func(org *Organization, userID string) error

	BeforeAddMember func(member *Member, userID string) error
	AfterAddMember  func(member *Member, userID string) error

	BeforeRemoveMember func(member *Member, userID string) error
	AfterRemoveMember  func(member *Member, userID string) error

	BeforeUpdateMemberRole func(member *Member, newRole string, userID string) error
	AfterUpdateMemberRole  func(member *Member, oldRole string, userID string) error

	BeforeCreateInvitation func(invitation *Invitation, inviterID string) error
	AfterCreateInvitation  func(invitation *Invitation, inviterID string) error

	BeforeAcceptInvitation func(invitation *Invitation, userID string) error
	AfterAcceptInvitation  func(invitation *Invitation, member *Member, userID string) error

	BeforeRejectInvitation func(invitation *Invitation, userID string) error
	AfterRejectInvitation  func(invitation *Invitation, userID string) error

	BeforeCancelInvitation func(invitation *Invitation, cancelledBy string) error
	AfterCancelInvitation  func(invitation *Invitation, cancelledBy string) error
}

// DefaultConfig returns the default configuration for the organization plugin.
func DefaultConfig() Config {
	return Config{
		AllowUserToCreateOrganization:      func(userID string) bool { return true },
		OrganizationLimit:                  func(userID string) int { return 10 },
		CreatorRole:                        "owner",
		MembershipLimit:                    100,
		InvitationExpiresIn:                48 * time.Hour, // 2 days
		CancelPendingInvitationsOnReInvite: true,
		Teams: TeamsConfig{
			Enabled:               false,
			MaximumTeams:          func(orgID string) int { return 10 },
			MaximumMembersPerTeam: func(teamID string) int { return 50 },
			AllowRemovingAllTeams: false,
		},
	}
}

// Option is a functional option for configuring the organization plugin.
type Option func(*Config)

// WithAccessControl sets the access control system.
func WithAccessControl(ac *access.AccessControl, roles map[string]*access.Role) Option {
	return func(c *Config) {
		c.AccessControl = ac
		c.Roles = roles
	}
}

// WithAllowUserToCreateOrganization sets whether users can create organizations.
func WithAllowUserToCreateOrganization(allow func(userID string) bool) Option {
	return func(c *Config) {
		c.AllowUserToCreateOrganization = allow
	}
}

// WithOrganizationLimit sets the maximum number of organizations per user.
func WithOrganizationLimit(limit func(userID string) int) Option {
	return func(c *Config) {
		c.OrganizationLimit = limit
	}
}

// WithCreatorRole sets the role assigned to organization creators.
func WithCreatorRole(role string) Option {
	return func(c *Config) {
		c.CreatorRole = role
	}
}

// WithMembershipLimit sets the maximum number of members per organization.
func WithMembershipLimit(limit int) Option {
	return func(c *Config) {
		c.MembershipLimit = limit
	}
}

// WithSendInvitationEmail sets the function to send invitation emails.
func WithSendInvitationEmail(sendFunc func(invitation *Invitation, organization *Organization) error) Option {
	return func(c *Config) {
		c.SendInvitationEmail = sendFunc
	}
}

// WithInvitationExpiresIn sets how long invitations are valid.
func WithInvitationExpiresIn(duration time.Duration) Option {
	return func(c *Config) {
		c.InvitationExpiresIn = duration
	}
}

// WithCancelPendingInvitationsOnReInvite sets whether to cancel pending invitations when re-inviting.
func WithCancelPendingInvitationsOnReInvite(cancel bool) Option {
	return func(c *Config) {
		c.CancelPendingInvitationsOnReInvite = cancel
	}
}

// WithTeams enables and configures teams.
func WithTeams(config TeamsConfig) Option {
	return func(c *Config) {
		c.Teams = config
	}
}

// WithOrganizationHooks sets the organization lifecycle hooks.
func WithOrganizationHooks(hooks OrganizationHooks) Option {
	return func(c *Config) {
		c.OrganizationHooks = hooks
	}
}
