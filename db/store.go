// Package db provides database store implementations using sqlc-generated queries.
// It supports PostgreSQL and SQLite through dialect-specific adapters that implement
// a common Querier interface. The dialect is selected once at initialization time,
// eliminating runtime branching in every method call.
package db

import (
	"context"
	"fmt"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
)

// Store implements models.Store using sqlc-generated queries.
// It delegates to a dialect-specific Querier implementation.
type Store struct {
	db      DBTX
	dialect Dialect
	q       Querier // The dialect-specific implementation
}

// New creates a new Store for the given dialect.
// The dialect determines which adapter (PostgreSQL or SQLite) is used.
// All subsequent operations use the selected adapter without runtime branching.
func New(db DBTX, dialect Dialect) (*Store, error) {
	var q Querier

	switch dialect {
	case DialectPostgres:
		q = newPgAdapter(db)
	case DialectSQLite:
		q = newSqliteAdapter(db)
	default:
		return nil, fmt.Errorf("unsupported dialect: %s", dialect)
	}

	return &Store{
		db:      db,
		dialect: dialect,
		q:       q,
	}, nil
}

// DB returns the underlying database connection.
// Implements plugin.DBProvider interface.
func (s *Store) DB() DBTX {
	return s.db
}

// Dialect returns the database dialect.
func (s *Store) Dialect() Dialect {
	return s.dialect
}

// Querier returns the underlying Querier for advanced use cases.
func (s *Store) Querier() Querier {
	return s.q
}

// PluginStore returns the store itself as a PluginStore.
// This allows the store to be used directly by plugins.
func (s *Store) PluginStore() PluginStore {
	return s
}

// =============================================================================
// UserStore Implementation - delegates to Querier
// =============================================================================

func (s *Store) CreateUser(ctx context.Context, user *models.User) error {
	return s.q.CreateUser(ctx, user)
}

func (s *Store) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	return s.q.GetUserByID(ctx, id)
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	return s.q.GetUserByEmail(ctx, email)
}

func (s *Store) UpdateUser(ctx context.Context, user *models.User) error {
	return s.q.UpdateUser(ctx, user)
}

func (s *Store) SetEmailVerified(ctx context.Context, userID string, verified bool) error {
	return s.q.SetEmailVerified(ctx, userID, verified)
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	return s.q.DeleteUser(ctx, id)
}

// =============================================================================
// AccountStore Implementation - delegates to Querier
// =============================================================================

func (s *Store) CreateAccount(ctx context.Context, account *models.Account) error {
	return s.q.CreateAccount(ctx, account)
}

func (s *Store) GetAccountByID(ctx context.Context, id string) (*models.Account, error) {
	return s.q.GetAccountByID(ctx, id)
}

func (s *Store) GetAccountByUserIDAndProvider(ctx context.Context, userID string, provider models.ProviderType) (*models.Account, error) {
	return s.q.GetAccountByUserIDAndProvider(ctx, userID, provider)
}

func (s *Store) GetAccountByProvider(ctx context.Context, provider models.ProviderType, providerAccountID string) (*models.Account, error) {
	return s.q.GetAccountByProvider(ctx, provider, providerAccountID)
}

func (s *Store) ListAccountsByUserID(ctx context.Context, userID string) ([]*models.Account, error) {
	return s.q.ListAccountsByUserID(ctx, userID)
}

func (s *Store) UpdateAccount(ctx context.Context, account *models.Account) error {
	return s.q.UpdateAccount(ctx, account)
}

func (s *Store) DeleteAccount(ctx context.Context, id string) error {
	return s.q.DeleteAccount(ctx, id)
}

func (s *Store) DeleteAccountsByUserID(ctx context.Context, userID string) error {
	return s.q.DeleteAccountsByUserID(ctx, userID)
}

// =============================================================================
// SessionStore Implementation - delegates to Querier
// =============================================================================

func (s *Store) CreateSession(ctx context.Context, session *models.Session) error {
	return s.q.CreateSession(ctx, session)
}

func (s *Store) GetSessionByID(ctx context.Context, id string) (*models.Session, error) {
	return s.q.GetSessionByID(ctx, id)
}

func (s *Store) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*models.Session, error) {
	return s.q.GetSessionByTokenHash(ctx, tokenHash)
}

func (s *Store) ListSessionsByUserID(ctx context.Context, userID string) ([]*models.Session, error) {
	return s.q.ListSessionsByUserID(ctx, userID)
}

func (s *Store) UpdateSessionLastUsed(ctx context.Context, id string) error {
	return s.q.UpdateSessionLastUsed(ctx, id)
}

func (s *Store) DeleteSession(ctx context.Context, id string) error {
	return s.q.DeleteSession(ctx, id)
}

func (s *Store) DeleteSessionsByUserID(ctx context.Context, userID string) error {
	return s.q.DeleteSessionsByUserID(ctx, userID)
}

func (s *Store) DeleteExpiredSessions(ctx context.Context) error {
	return s.q.DeleteExpiredSessions(ctx)
}

// =============================================================================
// VerificationStore Implementation - delegates to Querier
// =============================================================================

func (s *Store) CreateVerification(ctx context.Context, v *models.Verification) error {
	return s.q.CreateVerification(ctx, v)
}

func (s *Store) GetVerificationByTokenHash(ctx context.Context, tokenHash string) (*models.Verification, error) {
	return s.q.GetVerificationByTokenHash(ctx, tokenHash)
}

func (s *Store) DeleteVerification(ctx context.Context, id string) error {
	return s.q.DeleteVerification(ctx, id)
}

func (s *Store) DeleteVerificationsByUserIDAndType(ctx context.Context, userID string, vType models.VerificationType) error {
	return s.q.DeleteVerificationsByUserIDAndType(ctx, userID, vType)
}

func (s *Store) DeleteExpiredVerifications(ctx context.Context) error {
	return s.q.DeleteExpiredVerifications(ctx)
}

// =============================================================================
// OTP Store Methods - delegates to Querier
// =============================================================================

func (s *Store) CreateOTPToken(ctx context.Context, token *OTPToken) error {
	return s.q.CreateOTPToken(ctx, token)
}

func (s *Store) GetOTPTokenByHash(ctx context.Context, tokenHash string) (*OTPToken, error) {
	return s.q.GetOTPTokenByHash(ctx, tokenHash)
}

func (s *Store) DeleteOTPToken(ctx context.Context, id string) error {
	return s.q.DeleteOTPToken(ctx, id)
}

func (s *Store) DeleteOTPTokensByUserAndType(ctx context.Context, userID, tokenType string) error {
	return s.q.DeleteOTPTokensByUserAndType(ctx, userID, tokenType)
}

func (s *Store) DeleteExpiredOTPTokens(ctx context.Context) error {
	return s.q.DeleteExpiredOTPTokens(ctx)
}

// =============================================================================
// JWT Store Methods - delegates to Querier
// =============================================================================

func (s *Store) RevokeJWTToken(ctx context.Context, jti string, expiresAt time.Time) error {
	return s.q.RevokeJWTToken(ctx, jti, expiresAt)
}

func (s *Store) IsJWTTokenRevoked(ctx context.Context, jti string) (bool, error) {
	return s.q.IsJWTTokenRevoked(ctx, jti)
}

func (s *Store) DeleteExpiredRevokedTokens(ctx context.Context) error {
	return s.q.DeleteExpiredRevokedTokens(ctx)
}

// =============================================================================
// OAuth State Store Methods - delegates to Querier
// =============================================================================

func (s *Store) CreateOAuthState(ctx context.Context, state *OAuthState) error {
	return s.q.CreateOAuthState(ctx, state)
}

func (s *Store) GetOAuthState(ctx context.Context, state string) (*OAuthState, error) {
	return s.q.GetOAuthState(ctx, state)
}

func (s *Store) DeleteOAuthState(ctx context.Context, state string) error {
	return s.q.DeleteOAuthState(ctx, state)
}

func (s *Store) DeleteExpiredOAuthStates(ctx context.Context) error {
	return s.q.DeleteExpiredOAuthStates(ctx)
}

// =============================================================================
// OAuth Account Store Methods - delegates to Querier
// =============================================================================

func (s *Store) CreateOAuthAccount(ctx context.Context, account *OAuthAccount) error {
	return s.q.CreateOAuthAccount(ctx, account)
}

func (s *Store) GetOAuthAccountByProvider(ctx context.Context, provider, providerAccountID string) (*OAuthAccount, error) {
	return s.q.GetOAuthAccountByProvider(ctx, provider, providerAccountID)
}

func (s *Store) GetOAuthAccountsByUserID(ctx context.Context, userID string) ([]*OAuthAccount, error) {
	return s.q.GetOAuthAccountsByUserID(ctx, userID)
}

func (s *Store) UpdateOAuthAccount(ctx context.Context, account *OAuthAccount) error {
	return s.q.UpdateOAuthAccount(ctx, account)
}

func (s *Store) DeleteOAuthAccount(ctx context.Context, id string) error {
	return s.q.DeleteOAuthAccount(ctx, id)
}

// =============================================================================
// WebAuthn Credential Store Methods - delegates to Querier
// =============================================================================

func (s *Store) CreateWebAuthnCredential(ctx context.Context, cred *WebAuthnCredential) error {
	return s.q.CreateWebAuthnCredential(ctx, cred)
}

func (s *Store) GetWebAuthnCredentialByID(ctx context.Context, credentialID []byte) (*WebAuthnCredential, error) {
	return s.q.GetWebAuthnCredentialByID(ctx, credentialID)
}

func (s *Store) ListWebAuthnCredentialsByUserID(ctx context.Context, userID string) ([]*WebAuthnCredential, error) {
	return s.q.ListWebAuthnCredentialsByUserID(ctx, userID)
}

func (s *Store) UpdateWebAuthnCredentialSignCount(ctx context.Context, id string, signCount int64) error {
	return s.q.UpdateWebAuthnCredentialSignCount(ctx, id, signCount)
}

func (s *Store) DeleteWebAuthnCredential(ctx context.Context, id string) error {
	return s.q.DeleteWebAuthnCredential(ctx, id)
}

// =============================================================================
// WebAuthn Session Store Methods - delegates to Querier
// =============================================================================

func (s *Store) CreateWebAuthnSession(ctx context.Context, session *WebAuthnSession) error {
	return s.q.CreateWebAuthnSession(ctx, session)
}

func (s *Store) GetWebAuthnSession(ctx context.Context, id string) (*WebAuthnSession, error) {
	return s.q.GetWebAuthnSession(ctx, id)
}

func (s *Store) DeleteWebAuthnSession(ctx context.Context, id string) error {
	return s.q.DeleteWebAuthnSession(ctx, id)
}

func (s *Store) DeleteExpiredWebAuthnSessions(ctx context.Context) error {
	return s.q.DeleteExpiredWebAuthnSessions(ctx)
}

// =============================================================================
// API Key Store Methods - delegates to Querier
// =============================================================================

func (s *Store) CreateAPIKey(ctx context.Context, key *APIKey) error {
	return s.q.CreateAPIKey(ctx, key)
}

func (s *Store) GetAPIKeyByID(ctx context.Context, id string) (*APIKey, error) {
	return s.q.GetAPIKeyByID(ctx, id)
}

func (s *Store) GetAPIKeyByKeyPrefix(ctx context.Context, keyPrefix string) ([]*APIKey, error) {
	return s.q.GetAPIKeyByKeyPrefix(ctx, keyPrefix)
}

func (s *Store) ListAPIKeysByUserID(ctx context.Context, userID string) ([]*APIKey, error) {
	return s.q.ListAPIKeysByUserID(ctx, userID)
}

func (s *Store) UpdateAPIKey(ctx context.Context, key *APIKey) error {
	return s.q.UpdateAPIKey(ctx, key)
}

func (s *Store) UpdateAPIKeyUsage(ctx context.Context, key *APIKey) error {
	return s.q.UpdateAPIKeyUsage(ctx, key)
}

func (s *Store) DeleteAPIKey(ctx context.Context, id string) error {
	return s.q.DeleteAPIKey(ctx, id)
}

func (s *Store) DeleteAPIKeysByUserID(ctx context.Context, userID string) error {
	return s.q.DeleteAPIKeysByUserID(ctx, userID)
}

// =============================================================================
// JWT Key Store Methods - delegates to Querier
// =============================================================================

func (s *Store) CreateJWTKey(ctx context.Context, key *JWTKey) error {
	return s.q.CreateJWTKey(ctx, key)
}

func (s *Store) GetJWTKeyByID(ctx context.Context, id string) (*JWTKey, error) {
	return s.q.GetJWTKeyByID(ctx, id)
}

func (s *Store) GetActiveJWTKey(ctx context.Context, algorithm string) (*JWTKey, error) {
	return s.q.GetActiveJWTKey(ctx, algorithm)
}

func (s *Store) GetJWTKeysForVerification(ctx context.Context, algorithm string) ([]*JWTKey, error) {
	return s.q.GetJWTKeysForVerification(ctx, algorithm)
}

func (s *Store) GetJWTKeyForVerification(ctx context.Context, id string) (*JWTKey, error) {
	return s.q.GetJWTKeyForVerification(ctx, id)
}

func (s *Store) RotateActiveJWTKeys(ctx context.Context, algorithm string, expiresAt time.Time) error {
	return s.q.RotateActiveJWTKeys(ctx, algorithm, expiresAt)
}

func (s *Store) RetireExpiredJWTKeys(ctx context.Context) (int64, error) {
	return s.q.RetireExpiredJWTKeys(ctx)
}

func (s *Store) DeleteJWTKey(ctx context.Context, id string) error {
	return s.q.DeleteJWTKey(ctx, id)
}

// =============================================================================
// Password Plugin Store Methods - wrapper methods for password plugin
// =============================================================================

const providerEmail = "email"

// CreatePasswordAccount creates a new email/password account.
func (s *Store) CreatePasswordAccount(ctx context.Context, id, userID, passwordHash string) error {
	now := time.Now()
	account := &models.Account{
		ID:           id,
		UserID:       userID,
		Provider:     models.ProviderType(providerEmail),
		PasswordHash: &passwordHash,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	return s.q.CreateAccount(ctx, account)
}

// GetPasswordAccount retrieves the email account for a user.
func (s *Store) GetPasswordAccount(ctx context.Context, userID string) (*PasswordAccount, error) {
	account, err := s.q.GetAccountByUserIDAndProvider(ctx, userID, models.ProviderType(providerEmail))
	if err != nil {
		return nil, err
	}
	return &PasswordAccount{
		ID:           account.ID,
		UserID:       account.UserID,
		Provider:     string(account.Provider),
		PasswordHash: account.PasswordHash,
		CreatedAt:    account.CreatedAt,
		UpdatedAt:    account.UpdatedAt,
	}, nil
}

// UpdatePasswordHash updates the password hash for a user's email account.
func (s *Store) UpdatePasswordHash(ctx context.Context, userID, passwordHash string) error {
	account, err := s.q.GetAccountByUserIDAndProvider(ctx, userID, models.ProviderType(providerEmail))
	if err != nil {
		return err
	}
	account.PasswordHash = &passwordHash
	account.UpdatedAt = time.Now()
	return s.q.UpdateAccount(ctx, account)
}

// =============================================================================
// Admin Plugin Store Methods
// =============================================================================

// AdminListUsers returns a paginated list of users with optional filters.
func (s *Store) AdminListUsers(ctx context.Context, opts AdminListUsersOptions) (*AdminListUsersResult, error) {
	users, err := s.q.AdminListUsers(ctx, opts)
	if err != nil {
		return nil, err
	}

	count, err := s.q.AdminCountUsers(ctx, opts)
	if err != nil {
		return nil, err
	}

	result := make([]*AdminUser, len(users))
	for i, u := range users {
		result[i] = &AdminUser{
			ID:            u.ID,
			Email:         u.Email,
			EmailVerified: u.EmailVerified,
			Name:          u.Name,
			Image:         u.Image,
			Role:          u.Role,
			Banned:        u.Banned,
			BanReason:     u.BanReason,
			CreatedAt:     u.CreatedAt,
			UpdatedAt:     u.UpdatedAt,
		}
	}

	return &AdminListUsersResult{
		Users: result,
		Total: count,
	}, nil
}

// AdminGetUser retrieves a user by ID for admin operations.
func (s *Store) AdminGetUser(ctx context.Context, id string) (*AdminUser, error) {
	u, err := s.q.GetUserByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return &AdminUser{
		ID:            u.ID,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Name:          u.Name,
		Image:         u.Image,
		Role:          u.Role,
		Banned:        u.Banned,
		BanReason:     u.BanReason,
		CreatedAt:     u.CreatedAt,
		UpdatedAt:     u.UpdatedAt,
	}, nil
}

// AdminUpdateUser updates user fields for admin operations.
func (s *Store) AdminUpdateUser(ctx context.Context, user *AdminUser) error {
	return s.q.UpdateUser(ctx, &models.User{
		ID:            user.ID,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Name:          user.Name,
		Image:         user.Image,
		Role:          user.Role,
		Banned:        user.Banned,
		BanReason:     user.BanReason,
		CreatedAt:     user.CreatedAt,
		UpdatedAt:     user.UpdatedAt,
	})
}

// AdminDeleteUser deletes a user and all associated sessions/accounts.
func (s *Store) AdminDeleteUser(ctx context.Context, userID string) error {
	return s.q.AdminDeleteUserCascade(ctx, userID)
}

// AdminBanUser bans a user and revokes all their sessions.
func (s *Store) AdminBanUser(ctx context.Context, userID string, reason *string) error {
	if err := s.q.AdminBanUser(ctx, userID, reason); err != nil {
		return err
	}
	return s.q.DeleteSessionsByUserID(ctx, userID)
}

// AdminUnbanUser removes a ban from a user.
func (s *Store) AdminUnbanUser(ctx context.Context, userID string) error {
	return s.q.AdminUnbanUser(ctx, userID)
}

// AdminSetUserRole updates a user's role.
func (s *Store) AdminSetUserRole(ctx context.Context, userID, role string) error {
	return s.q.AdminSetUserRole(ctx, userID, role)
}

// =============================================================================
// Anonymous Plugin Store Methods
// =============================================================================

// SetAnonymousFlag updates the is_anonymous flag for a user.
func (s *Store) SetAnonymousFlag(ctx context.Context, userID string, isAnonymous bool) error {
	return s.q.SetAnonymousFlag(ctx, userID, isAnonymous)
}

// DeleteStaleAnonymousUsers deletes anonymous users older than the given cutoff time.
func (s *Store) DeleteStaleAnonymousUsers(ctx context.Context, cutoff time.Time) (int64, error) {
	return s.q.DeleteStaleAnonymousUsers(ctx, cutoff)
}

// EnsureAnonymousColumn ensures the is_anonymous column exists on the users table.
// This is a no-op for sqlc-based stores since the schema already includes the column.
func (s *Store) EnsureAnonymousColumn(ctx context.Context) error {
	// The column is already part of the schema, so this is a no-op.
	// For runtime migration, this could execute an ALTER TABLE if needed.
	return nil
}

// GetUserAnonymousStatus retrieves a user with their anonymous status.
func (s *Store) GetUserAnonymousStatus(ctx context.Context, userID string) (*AnonymousUser, error) {
	return s.q.GetUserWithAnonymousStatus(ctx, userID)
}

// =============================================================================
// Device Authorization Store Methods
// =============================================================================

// CreateDeviceCode stores a new device authorization code.
func (s *Store) CreateDeviceCode(ctx context.Context, code *DeviceCode) error {
	return s.q.CreateDeviceCode(ctx, code)
}

// GetDeviceCodeByUserCode retrieves a device code by user code.
func (s *Store) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error) {
	return s.q.GetDeviceCodeByUserCode(ctx, userCode)
}

// GetDeviceCodeByHash retrieves a device code by its hashed device code.
func (s *Store) GetDeviceCodeByHash(ctx context.Context, hashPrefix, fullHash string) (*DeviceCode, error) {
	return s.q.GetDeviceCodeByHash(ctx, hashPrefix, fullHash)
}

// UpdateDeviceCodeStatus updates the status and user ID of a device code.
func (s *Store) UpdateDeviceCodeStatus(ctx context.Context, id, status string, userID *string) error {
	return s.q.UpdateDeviceCodeStatus(ctx, id, status, userID)
}

// UpdateDeviceCodeLastPolled updates the last polled timestamp.
func (s *Store) UpdateDeviceCodeLastPolled(ctx context.Context, id string, lastPolledAt time.Time) error {
	return s.q.UpdateDeviceCodeLastPolled(ctx, id, lastPolledAt)
}

// DeleteExpiredDeviceCodes removes expired device codes.
func (s *Store) DeleteExpiredDeviceCodes(ctx context.Context) (int64, error) {
	return s.q.DeleteExpiredDeviceCodes(ctx)
}

// DeleteDeviceCode removes a device code by ID.
func (s *Store) DeleteDeviceCode(ctx context.Context, id string) error {
	return s.q.DeleteDeviceCode(ctx, id)
}

// =============================================================================
// Organization Store Methods - delegates to Querier
// =============================================================================

// CreateOrganization creates a new organization.
func (s *Store) CreateOrganization(ctx context.Context, org *Organization) error {
	return s.q.CreateOrganization(ctx, org)
}

// GetOrganizationByID retrieves an organization by ID.
func (s *Store) GetOrganizationByID(ctx context.Context, id string) (*Organization, error) {
	return s.q.GetOrganizationByID(ctx, id)
}

// GetOrganizationBySlug retrieves an organization by slug.
func (s *Store) GetOrganizationBySlug(ctx context.Context, slug string) (*Organization, error) {
	return s.q.GetOrganizationBySlug(ctx, slug)
}

// UpdateOrganization updates an organization.
func (s *Store) UpdateOrganization(ctx context.Context, org *Organization) error {
	return s.q.UpdateOrganization(ctx, org)
}

// DeleteOrganization deletes an organization by ID.
func (s *Store) DeleteOrganization(ctx context.Context, id string) error {
	return s.q.DeleteOrganization(ctx, id)
}

// ListUserOrganizations returns all organizations a user is a member of.
func (s *Store) ListUserOrganizations(ctx context.Context, userID string) ([]*Organization, error) {
	return s.q.ListUserOrganizations(ctx, userID)
}

// CheckSlugExists checks if an organization slug already exists.
func (s *Store) CheckSlugExists(ctx context.Context, slug string) (bool, error) {
	return s.q.CheckSlugExists(ctx, slug)
}

// =============================================================================
// Member Store Methods - delegates to Querier
// =============================================================================

// CreateMember adds a member to an organization.
func (s *Store) CreateMember(ctx context.Context, member *OrgMember) error {
	return s.q.CreateMember(ctx, member)
}

// GetMember retrieves a member by organization ID and user ID.
func (s *Store) GetMember(ctx context.Context, orgID, userID string) (*OrgMember, error) {
	return s.q.GetMember(ctx, orgID, userID)
}

// GetMemberByID retrieves a member by ID.
func (s *Store) GetMemberByID(ctx context.Context, id string) (*OrgMember, error) {
	return s.q.GetMemberByID(ctx, id)
}

// ListMembersByOrganization returns all members of an organization.
func (s *Store) ListMembersByOrganization(ctx context.Context, orgID string) ([]*OrgMember, error) {
	return s.q.ListMembersByOrganization(ctx, orgID)
}

// ListMembersByUser returns all memberships for a user.
func (s *Store) ListMembersByUser(ctx context.Context, userID string) ([]*OrgMember, error) {
	return s.q.ListMembersByUser(ctx, userID)
}

// UpdateMemberRole updates a member's role.
func (s *Store) UpdateMemberRole(ctx context.Context, id, role string, updatedAt time.Time) error {
	return s.q.UpdateMemberRole(ctx, id, role, updatedAt)
}

// DeleteMember removes a member from an organization.
func (s *Store) DeleteMember(ctx context.Context, orgID, userID string) error {
	return s.q.DeleteMember(ctx, orgID, userID)
}

// CountOrganizationMembers returns the number of members in an organization.
func (s *Store) CountOrganizationMembers(ctx context.Context, orgID string) (int64, error) {
	return s.q.CountOrganizationMembers(ctx, orgID)
}

// GetFirstMemberByUser returns the first membership for a user.
func (s *Store) GetFirstMemberByUser(ctx context.Context, userID string) (*OrgMember, error) {
	return s.q.GetFirstMemberByUser(ctx, userID)
}

// =============================================================================
// Invitation Store Methods - delegates to Querier
// =============================================================================

// CreateInvitation creates a new invitation.
func (s *Store) CreateInvitation(ctx context.Context, inv *OrgInvitation) error {
	return s.q.CreateInvitation(ctx, inv)
}

// GetInvitationByID retrieves an invitation by ID.
func (s *Store) GetInvitationByID(ctx context.Context, id string) (*OrgInvitation, error) {
	return s.q.GetInvitationByID(ctx, id)
}

// GetPendingInvitationByEmailAndOrg retrieves a pending invitation by email and org.
func (s *Store) GetPendingInvitationByEmailAndOrg(ctx context.Context, email, orgID string) (*OrgInvitation, error) {
	return s.q.GetPendingInvitationByEmailAndOrg(ctx, email, orgID)
}

// ListInvitationsByOrganization returns all invitations for an organization.
func (s *Store) ListInvitationsByOrganization(ctx context.Context, orgID string) ([]*OrgInvitation, error) {
	return s.q.ListInvitationsByOrganization(ctx, orgID)
}

// ListPendingInvitationsByEmail returns all pending invitations for an email.
func (s *Store) ListPendingInvitationsByEmail(ctx context.Context, email string) ([]*OrgInvitation, error) {
	return s.q.ListPendingInvitationsByEmail(ctx, email)
}

// UpdateInvitationStatus updates an invitation's status.
func (s *Store) UpdateInvitationStatus(ctx context.Context, id, status string) error {
	return s.q.UpdateInvitationStatus(ctx, id, status)
}

// CancelPendingInvitations cancels all pending invitations for an email and org.
func (s *Store) CancelPendingInvitations(ctx context.Context, email, orgID string) error {
	return s.q.CancelPendingInvitations(ctx, email, orgID)
}

// DeleteExpiredInvitations removes expired invitations.
func (s *Store) DeleteExpiredInvitations(ctx context.Context) (int64, error) {
	return s.q.DeleteExpiredInvitations(ctx)
}

// =============================================================================
// Team Store Methods - delegates to Querier
// =============================================================================

// CreateTeam creates a new team.
func (s *Store) CreateTeam(ctx context.Context, team *OrgTeam) error {
	return s.q.CreateTeam(ctx, team)
}

// GetTeamByID retrieves a team by ID.
func (s *Store) GetTeamByID(ctx context.Context, id string) (*OrgTeam, error) {
	return s.q.GetTeamByID(ctx, id)
}

// ListTeamsByOrganization returns all teams for an organization.
func (s *Store) ListTeamsByOrganization(ctx context.Context, orgID string) ([]*OrgTeam, error) {
	return s.q.ListTeamsByOrganization(ctx, orgID)
}

// UpdateTeam updates a team.
func (s *Store) UpdateTeam(ctx context.Context, id, name string, updatedAt time.Time) error {
	return s.q.UpdateTeam(ctx, id, name, updatedAt)
}

// DeleteTeam deletes a team by ID.
func (s *Store) DeleteTeam(ctx context.Context, id string) error {
	return s.q.DeleteTeam(ctx, id)
}

// =============================================================================
// Team Member Store Methods - delegates to Querier
// =============================================================================

// CreateTeamMember adds a member to a team.
func (s *Store) CreateTeamMember(ctx context.Context, member *OrgTeamMember) error {
	return s.q.CreateTeamMember(ctx, member)
}

// GetTeamMember retrieves a team member by team ID and user ID.
func (s *Store) GetTeamMember(ctx context.Context, teamID, userID string) (*OrgTeamMember, error) {
	return s.q.GetTeamMember(ctx, teamID, userID)
}

// ListTeamMembersByTeam returns all members of a team.
func (s *Store) ListTeamMembersByTeam(ctx context.Context, teamID string) ([]*OrgTeamMember, error) {
	return s.q.ListTeamMembersByTeam(ctx, teamID)
}

// ListTeamMembersByUser returns all team memberships for a user.
func (s *Store) ListTeamMembersByUser(ctx context.Context, userID string) ([]*OrgTeamMember, error) {
	return s.q.ListTeamMembersByUser(ctx, userID)
}

// DeleteTeamMember removes a member from a team.
func (s *Store) DeleteTeamMember(ctx context.Context, teamID, userID string) error {
	return s.q.DeleteTeamMember(ctx, teamID, userID)
}
