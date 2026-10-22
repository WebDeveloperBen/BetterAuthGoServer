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
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	PrepareContext(context.Context, string) (*sql.Stmt, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// Querier defines all database operations for the auth package.
// Each dialect implements this interface, handling type conversions internally.
type Querier interface {
	// User operations
	CreateUser(ctx context.Context, user *models.User) error
	GetUserByID(ctx context.Context, id string) (*models.User, error)
	GetUsersByIDs(ctx context.Context, userIDs []string) ([]*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	UpdateUser(ctx context.Context, user *models.User) error
	SetEmailVerified(ctx context.Context, userID string, verified bool) error
	DeleteUser(ctx context.Context, id string) error
	// LockUser locks the user's row (SQLite: the database for writing) until the
	// enclosing transaction ends. Returns models.ErrUserNotFound if the user does not exist.
	LockUser(ctx context.Context, id string) error

	// Account operations
	CreateAccount(ctx context.Context, account *models.Account) error
	GetAccountByID(ctx context.Context, id string) (*models.Account, error)
	GetAccountByUserIDAndProvider(ctx context.Context, userID string, provider models.ProviderType) (*models.Account, error)
	GetAccountByProvider(ctx context.Context, provider models.ProviderType, providerAccountID string) (*models.Account, error)
	ListAccountsByUserID(ctx context.Context, userID string) ([]*models.Account, error)
	ListAccountsByUserIDs(ctx context.Context, userIDs []string) ([]*models.Account, error)
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
}
