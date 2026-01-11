package db

import (
	"context"
	"time"
)

// PluginStore defines the interface that plugins use for database operations.
// This provides a clean abstraction that hides the underlying database implementation.
type PluginStore interface {
	// OTP operations
	OTPStore

	// JWT operations
	JWTStore

	// JWT Key operations
	JWTKeyStore

	// OAuth operations
	OAuthStore

	// WebAuthn operations
	WebAuthnStore

	// API Key operations
	APIKeyStore

	// Password operations (account and session management)
	PasswordPluginStore

	// Admin operations
	AdminPluginStore

	// Anonymous operations
	AnonymousPluginStore

	// Device Authorization operations
	DeviceAuthStore

	// Organization operations
	OrganizationStore
}

// OTPStore defines OTP token operations for plugins.
type OTPStore interface {
	CreateOTPToken(ctx context.Context, token *OTPToken) error
	GetOTPTokenByHash(ctx context.Context, tokenHash string) (*OTPToken, error)
	DeleteOTPToken(ctx context.Context, id string) error
	DeleteOTPTokensByUserAndType(ctx context.Context, userID, tokenType string) error
	DeleteExpiredOTPTokens(ctx context.Context) error
}

// JWTStore defines JWT revocation operations for plugins.
type JWTStore interface {
	RevokeJWTToken(ctx context.Context, jti string, expiresAt time.Time) error
	IsJWTTokenRevoked(ctx context.Context, jti string) (bool, error)
	DeleteExpiredRevokedTokens(ctx context.Context) error
}

// JWTKeyStore defines JWT key management operations for plugins.
type JWTKeyStore interface {
	CreateJWTKey(ctx context.Context, key *JWTKey) error
	GetJWTKeyByID(ctx context.Context, id string) (*JWTKey, error)
	GetActiveJWTKey(ctx context.Context, algorithm string) (*JWTKey, error)
	GetJWTKeysForVerification(ctx context.Context, algorithm string) ([]*JWTKey, error)
	GetJWTKeyForVerification(ctx context.Context, id string) (*JWTKey, error)
	RotateActiveJWTKeys(ctx context.Context, algorithm string, expiresAt time.Time) error
	RetireExpiredJWTKeys(ctx context.Context) (int64, error)
	DeleteJWTKey(ctx context.Context, id string) error
}

// OAuthStore defines OAuth operations for plugins.
type OAuthStore interface {
	// State management
	CreateOAuthState(ctx context.Context, state *OAuthState) error
	GetOAuthState(ctx context.Context, state string) (*OAuthState, error)
	DeleteOAuthState(ctx context.Context, state string) error
	DeleteExpiredOAuthStates(ctx context.Context) error

	// Account management
	CreateOAuthAccount(ctx context.Context, account *OAuthAccount) error
	GetOAuthAccountByProvider(ctx context.Context, provider, providerAccountID string) (*OAuthAccount, error)
	GetOAuthAccountsByUserID(ctx context.Context, userID string) ([]*OAuthAccount, error)
	UpdateOAuthAccount(ctx context.Context, account *OAuthAccount) error
	DeleteOAuthAccount(ctx context.Context, id string) error
}

// WebAuthnStore defines WebAuthn operations for plugins.
type WebAuthnStore interface {
	// Credential operations
	CreateWebAuthnCredential(ctx context.Context, cred *WebAuthnCredential) error
	GetWebAuthnCredentialByID(ctx context.Context, credentialID []byte) (*WebAuthnCredential, error)
	ListWebAuthnCredentialsByUserID(ctx context.Context, userID string) ([]*WebAuthnCredential, error)
	UpdateWebAuthnCredentialSignCount(ctx context.Context, id string, signCount int64) error
	DeleteWebAuthnCredential(ctx context.Context, id string) error

	// Session operations
	CreateWebAuthnSession(ctx context.Context, session *WebAuthnSession) error
	GetWebAuthnSession(ctx context.Context, id string) (*WebAuthnSession, error)
	DeleteWebAuthnSession(ctx context.Context, id string) error
	DeleteExpiredWebAuthnSessions(ctx context.Context) error
}

// APIKeyStore defines API key operations for plugins.
type APIKeyStore interface {
	CreateAPIKey(ctx context.Context, key *APIKey) error
	GetAPIKeyByID(ctx context.Context, id string) (*APIKey, error)
	GetAPIKeyByKeyPrefix(ctx context.Context, keyPrefix string) ([]*APIKey, error)
	ListAPIKeysByUserID(ctx context.Context, userID string) ([]*APIKey, error)
	UpdateAPIKey(ctx context.Context, key *APIKey) error
	UpdateAPIKeyUsage(ctx context.Context, key *APIKey) error
	DeleteAPIKey(ctx context.Context, id string) error
	DeleteAPIKeysByUserID(ctx context.Context, userID string) error
}

// PasswordPluginStore defines account and session operations for the password plugin.
type PasswordPluginStore interface {
	CreatePasswordAccount(ctx context.Context, id, userID, passwordHash string) error
	GetPasswordAccount(ctx context.Context, userID string) (*PasswordAccount, error)
	UpdatePasswordHash(ctx context.Context, userID, passwordHash string) error
	DeleteSessionsByUserID(ctx context.Context, userID string) error
}

// PasswordAccount is a simplified account type for the password plugin.
type PasswordAccount struct {
	ID           string
	UserID       string
	Provider     string
	PasswordHash *string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// AdminPluginStore defines user management operations for the admin plugin.
type AdminPluginStore interface {
	// AdminListUsers returns a paginated list of users with optional filters.
	AdminListUsers(ctx context.Context, opts AdminListUsersOptions) (*AdminListUsersResult, error)
	// AdminGetUser retrieves a user by ID for admin operations.
	AdminGetUser(ctx context.Context, id string) (*AdminUser, error)
	// AdminUpdateUser updates user fields for admin operations.
	AdminUpdateUser(ctx context.Context, user *AdminUser) error
	// AdminDeleteUser deletes a user and all associated sessions/accounts.
	AdminDeleteUser(ctx context.Context, userID string) error
	// AdminBanUser bans a user and revokes all their sessions.
	AdminBanUser(ctx context.Context, userID string, reason *string) error
	// AdminUnbanUser removes a ban from a user.
	AdminUnbanUser(ctx context.Context, userID string) error
	// AdminSetUserRole updates a user's role.
	AdminSetUserRole(ctx context.Context, userID, role string) error
}

// AdminListUsersOptions defines options for listing users.
type AdminListUsersOptions struct {
	Query  string // Search query for name or email
	Role   string // Filter by role
	Offset int    // Pagination offset
	Limit  int    // Pagination limit
}

// AdminListUsersResult contains the paginated list result.
type AdminListUsersResult struct {
	Users []*AdminUser
	Total int64
}

// AdminUser represents a user for admin operations.
type AdminUser struct {
	ID            string
	Email         string
	EmailVerified bool
	Name          string
	Image         *string
	Role          string
	Banned        bool
	BanReason     *string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// AnonymousPluginStore defines operations for the anonymous plugin.
type AnonymousPluginStore interface {
	// SetAnonymousFlag updates the is_anonymous flag for a user.
	SetAnonymousFlag(ctx context.Context, userID string, isAnonymous bool) error
	// DeleteStaleAnonymousUsers deletes anonymous users older than the given cutoff time.
	DeleteStaleAnonymousUsers(ctx context.Context, cutoff time.Time) (int64, error)
	// EnsureAnonymousColumn ensures the is_anonymous column exists on the users table.
	EnsureAnonymousColumn(ctx context.Context) error
	// GetUserAnonymousStatus retrieves a user with their anonymous status.
	GetUserAnonymousStatus(ctx context.Context, userID string) (*AnonymousUser, error)
}

// AnonymousUser represents a user with anonymous status.
type AnonymousUser struct {
	ID            string
	Email         string
	EmailVerified bool
	Name          string
	Image         *string
	Role          string
	Banned        bool
	IsAnonymous   bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// DeviceAuthStore defines device authorization operations for plugins.
type DeviceAuthStore interface {
	// CreateDeviceCode stores a new device authorization code.
	CreateDeviceCode(ctx context.Context, code *DeviceCode) error
	// GetDeviceCodeByUserCode retrieves a device code by user code.
	GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error)
	// GetDeviceCodeByHash retrieves a device code by its hashed device code.
	GetDeviceCodeByHash(ctx context.Context, hashPrefix, fullHash string) (*DeviceCode, error)
	// UpdateDeviceCodeStatus updates the status and user ID of a device code.
	UpdateDeviceCodeStatus(ctx context.Context, id, status string, userID *string) error
	// UpdateDeviceCodeLastPolled updates the last polled timestamp.
	UpdateDeviceCodeLastPolled(ctx context.Context, id string, lastPolledAt time.Time) error
	// DeleteExpiredDeviceCodes removes expired device codes.
	DeleteExpiredDeviceCodes(ctx context.Context) (int64, error)
	// DeleteDeviceCode removes a device code by ID.
	DeleteDeviceCode(ctx context.Context, id string) error
}

// OrganizationStore defines organization operations for plugins.
type OrganizationStore interface {
	// Organizations
	CreateOrganization(ctx context.Context, org *Organization) error
	GetOrganizationByID(ctx context.Context, id string) (*Organization, error)
	GetOrganizationBySlug(ctx context.Context, slug string) (*Organization, error)
	UpdateOrganization(ctx context.Context, org *Organization) error
	DeleteOrganization(ctx context.Context, id string) error
	ListUserOrganizations(ctx context.Context, userID string) ([]*Organization, error)
	CheckSlugExists(ctx context.Context, slug string) (bool, error)

	// Members
	CreateMember(ctx context.Context, member *OrgMember) error
	GetMember(ctx context.Context, orgID, userID string) (*OrgMember, error)
	GetMemberByID(ctx context.Context, id string) (*OrgMember, error)
	ListMembersByOrganization(ctx context.Context, orgID string) ([]*OrgMember, error)
	ListMembersByUser(ctx context.Context, userID string) ([]*OrgMember, error)
	UpdateMemberRole(ctx context.Context, id, role string, updatedAt time.Time) error
	DeleteMember(ctx context.Context, orgID, userID string) error
	CountOrganizationMembers(ctx context.Context, orgID string) (int64, error)
	GetFirstMemberByUser(ctx context.Context, userID string) (*OrgMember, error)

	// Invitations
	CreateInvitation(ctx context.Context, inv *OrgInvitation) error
	GetInvitationByID(ctx context.Context, id string) (*OrgInvitation, error)
	GetPendingInvitationByEmailAndOrg(ctx context.Context, email, orgID string) (*OrgInvitation, error)
	ListInvitationsByOrganization(ctx context.Context, orgID string) ([]*OrgInvitation, error)
	ListPendingInvitationsByEmail(ctx context.Context, email string) ([]*OrgInvitation, error)
	UpdateInvitationStatus(ctx context.Context, id, status string) error
	CancelPendingInvitations(ctx context.Context, email, orgID string) error
	DeleteExpiredInvitations(ctx context.Context) (int64, error)

	// Teams
	CreateTeam(ctx context.Context, team *OrgTeam) error
	GetTeamByID(ctx context.Context, id string) (*OrgTeam, error)
	ListTeamsByOrganization(ctx context.Context, orgID string) ([]*OrgTeam, error)
	UpdateTeam(ctx context.Context, id, name string, updatedAt time.Time) error
	DeleteTeam(ctx context.Context, id string) error

	// Team Members
	CreateTeamMember(ctx context.Context, member *OrgTeamMember) error
	GetTeamMember(ctx context.Context, teamID, userID string) (*OrgTeamMember, error)
	ListTeamMembersByTeam(ctx context.Context, teamID string) ([]*OrgTeamMember, error)
	ListTeamMembersByUser(ctx context.Context, userID string) ([]*OrgTeamMember, error)
	DeleteTeamMember(ctx context.Context, teamID, userID string) error
}

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

// OrgMember represents a membership in an organization.
type OrgMember struct {
	ID             string
	OrganizationID string
	UserID         string
	Role           string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// OrgInvitation represents an invitation to join an organization.
type OrgInvitation struct {
	ID             string
	Email          string
	OrganizationID string
	InviterID      string
	Role           string
	Status         string
	ExpiresAt      *time.Time
	CreatedAt      time.Time
}

// OrgTeam represents a team within an organization.
type OrgTeam struct {
	ID             string
	Name           string
	OrganizationID string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// OrgTeamMember represents a membership in a team.
type OrgTeamMember struct {
	ID        string
	TeamID    string
	UserID    string
	CreatedAt time.Time
}

// Ensure Store implements PluginStore
var _ PluginStore = (*Store)(nil)
