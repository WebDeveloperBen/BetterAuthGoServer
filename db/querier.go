// Package db provides database store implementations using sqlc-generated queries.
// It supports PostgreSQL and SQLite through dialect-specific adapters.
package db

import (
	"context"
	"database/sql"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
)

// Dialect represents the database dialect
type Dialect string

const (
	DialectPostgres Dialect = "postgres"
	DialectSQLite   Dialect = "sqlite"
	DialectMySQL    Dialect = "mysql"
)

// DBTX is the database interface used by the store.
// Satisfied by *sql.DB, *sql.Tx, and other compatible types.
type DBTX interface {
	ExecContext(context.Context, string, ...interface{}) (sql.Result, error)
	PrepareContext(context.Context, string) (*sql.Stmt, error)
	QueryContext(context.Context, string, ...interface{}) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...interface{}) *sql.Row
}

// Querier defines all database operations for the auth package.
// Each dialect implements this interface, handling type conversions internally.
type Querier interface {
	// User operations
	CreateUser(ctx context.Context, user *models.User) error
	GetUserByID(ctx context.Context, id string) (*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	UpdateUser(ctx context.Context, user *models.User) error
	SetEmailVerified(ctx context.Context, userID string, verified bool) error
	DeleteUser(ctx context.Context, id string) error

	// Account operations
	CreateAccount(ctx context.Context, account *models.Account) error
	GetAccountByID(ctx context.Context, id string) (*models.Account, error)
	GetAccountByUserIDAndProvider(ctx context.Context, userID string, provider models.ProviderType) (*models.Account, error)
	GetAccountByProvider(ctx context.Context, provider models.ProviderType, providerAccountID string) (*models.Account, error)
	ListAccountsByUserID(ctx context.Context, userID string) ([]*models.Account, error)
	UpdateAccount(ctx context.Context, account *models.Account) error
	DeleteAccount(ctx context.Context, id string) error
	DeleteAccountsByUserID(ctx context.Context, userID string) error

	// Session operations
	CreateSession(ctx context.Context, session *models.Session) error
	GetSessionByID(ctx context.Context, id string) (*models.Session, error)
	GetSessionByTokenHash(ctx context.Context, tokenHash string) (*models.Session, error)
	ListSessionsByUserID(ctx context.Context, userID string) ([]*models.Session, error)
	UpdateSessionLastUsed(ctx context.Context, id string) error
	DeleteSession(ctx context.Context, id string) error
	DeleteSessionsByUserID(ctx context.Context, userID string) error
	DeleteExpiredSessions(ctx context.Context) error

	// Verification operations
	CreateVerification(ctx context.Context, v *models.Verification) error
	GetVerificationByTokenHash(ctx context.Context, tokenHash string) (*models.Verification, error)
	DeleteVerification(ctx context.Context, id string) error
	DeleteVerificationsByUserIDAndType(ctx context.Context, userID string, vType models.VerificationType) error
	DeleteExpiredVerifications(ctx context.Context) error

	// OTP operations
	CreateOTPToken(ctx context.Context, token *OTPToken) error
	GetOTPTokenByHash(ctx context.Context, tokenHash string) (*OTPToken, error)
	DeleteOTPToken(ctx context.Context, id string) error
	DeleteOTPTokensByUserAndType(ctx context.Context, userID, tokenType string) error
	DeleteExpiredOTPTokens(ctx context.Context) error

	// JWT operations
	RevokeJWTToken(ctx context.Context, jti string, expiresAt time.Time) error
	IsJWTTokenRevoked(ctx context.Context, jti string) (bool, error)
	DeleteExpiredRevokedTokens(ctx context.Context) error

	// JWT Key operations
	CreateJWTKey(ctx context.Context, key *JWTKey) error
	GetJWTKeyByID(ctx context.Context, id string) (*JWTKey, error)
	GetActiveJWTKey(ctx context.Context, algorithm string) (*JWTKey, error)
	GetJWTKeysForVerification(ctx context.Context, algorithm string) ([]*JWTKey, error)
	GetJWTKeyForVerification(ctx context.Context, id string) (*JWTKey, error)
	RotateActiveJWTKeys(ctx context.Context, algorithm string, expiresAt time.Time) error
	RetireExpiredJWTKeys(ctx context.Context) (int64, error)
	DeleteJWTKey(ctx context.Context, id string) error

	// OAuth State operations
	CreateOAuthState(ctx context.Context, state *OAuthState) error
	GetOAuthState(ctx context.Context, state string) (*OAuthState, error)
	DeleteOAuthState(ctx context.Context, state string) error
	DeleteExpiredOAuthStates(ctx context.Context) error

	// OAuth Account operations
	CreateOAuthAccount(ctx context.Context, account *OAuthAccount) error
	GetOAuthAccountByProvider(ctx context.Context, provider, providerAccountID string) (*OAuthAccount, error)
	GetOAuthAccountsByUserID(ctx context.Context, userID string) ([]*OAuthAccount, error)
	UpdateOAuthAccount(ctx context.Context, account *OAuthAccount) error
	DeleteOAuthAccount(ctx context.Context, id string) error

	// WebAuthn Credential operations
	CreateWebAuthnCredential(ctx context.Context, cred *WebAuthnCredential) error
	GetWebAuthnCredentialByID(ctx context.Context, credentialID []byte) (*WebAuthnCredential, error)
	ListWebAuthnCredentialsByUserID(ctx context.Context, userID string) ([]*WebAuthnCredential, error)
	UpdateWebAuthnCredentialSignCount(ctx context.Context, id string, signCount int64) error
	DeleteWebAuthnCredential(ctx context.Context, id string) error

	// WebAuthn Session operations
	CreateWebAuthnSession(ctx context.Context, session *WebAuthnSession) error
	GetWebAuthnSession(ctx context.Context, id string) (*WebAuthnSession, error)
	DeleteWebAuthnSession(ctx context.Context, id string) error
	DeleteExpiredWebAuthnSessions(ctx context.Context) error

	// API Key operations
	CreateAPIKey(ctx context.Context, key *APIKey) error
	GetAPIKeyByID(ctx context.Context, id string) (*APIKey, error)
	GetAPIKeyByKeyPrefix(ctx context.Context, keyPrefix string) ([]*APIKey, error)
	ListAPIKeysByUserID(ctx context.Context, userID string) ([]*APIKey, error)
	UpdateAPIKey(ctx context.Context, key *APIKey) error
	UpdateAPIKeyUsage(ctx context.Context, key *APIKey) error
	DeleteAPIKey(ctx context.Context, id string) error
	DeleteAPIKeysByUserID(ctx context.Context, userID string) error

	// Admin operations
	AdminListUsers(ctx context.Context, opts AdminListUsersOptions) ([]*models.User, error)
	AdminCountUsers(ctx context.Context, opts AdminListUsersOptions) (int64, error)
	AdminBanUser(ctx context.Context, userID string, reason *string) error
	AdminUnbanUser(ctx context.Context, userID string) error
	AdminSetUserRole(ctx context.Context, userID, role string) error
	AdminDeleteUserCascade(ctx context.Context, userID string) error

	// Anonymous operations
	SetAnonymousFlag(ctx context.Context, userID string, isAnonymous bool) error
	DeleteStaleAnonymousUsers(ctx context.Context, cutoff time.Time) (int64, error)
	GetUserWithAnonymousStatus(ctx context.Context, userID string) (*AnonymousUser, error)

	// Device Authorization operations
	CreateDeviceCode(ctx context.Context, code *DeviceCode) error
	GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error)
	GetDeviceCodeByHash(ctx context.Context, hashPrefix, fullHash string) (*DeviceCode, error)
	UpdateDeviceCodeStatus(ctx context.Context, id, status string, userID *string) error
	UpdateDeviceCodeLastPolled(ctx context.Context, id string, lastPolledAt time.Time) error
	DeleteExpiredDeviceCodes(ctx context.Context) (int64, error)
	DeleteDeviceCode(ctx context.Context, id string) error
}
