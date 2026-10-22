// Package db provides database store implementations using sqlc-generated queries.
// It supports PostgreSQL and SQLite through dialect-specific adapters that implement
// a common Querier interface. The dialect is selected once at initialization time,
// eliminating runtime branching in every method call.
package db

import (
	"context"
	"database/sql"
	"errors"
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
	case DialectMySQL:
		q = newMysqlAdapter(db)
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

// ErrTxUnsupported is returned by InTx when the underlying connection cannot begin transactions
// (for example when the Store was created on an existing *sql.Tx).
var ErrTxUnsupported = errors.New("db: transactions not supported by the underlying connection")

// txBeginner is implemented by *sql.DB.
type txBeginner interface {
	BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error)
}

// InTx runs fn inside a database transaction. fn receives a Store bound to the transaction
// and the transaction itself, so plugin stores can join the same unit of work.
// The transaction is committed when fn returns nil and rolled back otherwise,
// including when fn panics.
func (s *Store) InTx(ctx context.Context, fn func(txStore *Store, tx DBTX) error) (err error) {
	beginner, ok := s.db.(txBeginner)
	if !ok {
		return ErrTxUnsupported
	}

	tx, err := beginner.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("db: begin transaction: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if rbErr := tx.Rollback(); rbErr != nil && err != nil {
			err = errors.Join(err, fmt.Errorf("db: rollback: %w", rbErr))
		}
	}()

	txStore, err := New(tx, s.dialect)
	if err != nil {
		return err
	}
	if err := fn(txStore, tx); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("db: commit transaction: %w", err)
	}
	committed = true
	return nil
}

// =============================================================================
// UserStore Implementation - delegates to Querier
//
// Emails are stored and looked up in normalized form (models.NormalizeEmail), so
// addresses that differ only in case or surrounding whitespace match the same user.
// =============================================================================

func (s *Store) CreateUser(ctx context.Context, user *models.User) error {
	user.Email = models.NormalizeEmail(user.Email)
	return s.q.CreateUser(ctx, user)
}

func (s *Store) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	return s.q.GetUserByID(ctx, id)
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	return s.q.GetUserByEmail(ctx, models.NormalizeEmail(email))
}

func (s *Store) UpdateUser(ctx context.Context, user *models.User) error {
	user.Email = models.NormalizeEmail(user.Email)
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
		Email:         models.NormalizeEmail(user.Email),
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
