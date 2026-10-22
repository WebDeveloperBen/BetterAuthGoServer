package db

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/db/mysqlstore"
)

// mysqlAdapter implements Querier using MySQL-specific sqlc queries.
type mysqlAdapter struct {
	q *mysqlstore.Queries
}

// newMysqlAdapter creates a new MySQL adapter.
func newMysqlAdapter(db DBTX) *mysqlAdapter {
	return &mysqlAdapter{q: mysqlstore.New(db)}
}

// =============================================================================
// User operations
// =============================================================================

func (a *mysqlAdapter) CreateUser(ctx context.Context, user *models.User) error {
	return a.q.CreateUser(ctx, mysqlstore.CreateUserParams{
		ID:            user.ID,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Name:          user.Name,
		Image:         toNullString(user.Image),
		Banned:        user.Banned,
		BannedAt:      toNullTime(user.BannedAt),
		BanReason:     toNullString(user.BanReason),
		Role:          user.Role,
		CreatedAt:     user.CreatedAt,
		UpdatedAt:     user.UpdatedAt,
	})
}

func (a *mysqlAdapter) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	u, err := a.q.GetUserByID(ctx, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return mysqlUserToModel(&u), nil
}

func (a *mysqlAdapter) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	u, err := a.q.GetUserByEmail(ctx, email)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return mysqlUserToModel(&u), nil
}

func (a *mysqlAdapter) UpdateUser(ctx context.Context, user *models.User) error {
	return a.q.UpdateUser(ctx, mysqlstore.UpdateUserParams{
		ID:            user.ID,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Name:          user.Name,
		Image:         toNullString(user.Image),
		Banned:        user.Banned,
		BannedAt:      toNullTime(user.BannedAt),
		BanReason:     toNullString(user.BanReason),
		Role:          user.Role,
		UpdatedAt:     time.Now(),
	})
}

func (a *mysqlAdapter) SetEmailVerified(ctx context.Context, userID string, verified bool) error {
	return a.q.SetEmailVerified(ctx, mysqlstore.SetEmailVerifiedParams{
		ID:            userID,
		EmailVerified: verified,
		UpdatedAt:     time.Now(),
	})
}

func (a *mysqlAdapter) DeleteUser(ctx context.Context, id string) error {
	return a.q.DeleteUser(ctx, id)
}

func (a *mysqlAdapter) LockUser(ctx context.Context, id string) error {
	_, err := a.q.LockUser(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return models.ErrUserNotFound
	}
	return err
}

// =============================================================================
// Account operations
// =============================================================================

func (a *mysqlAdapter) CreateAccount(ctx context.Context, account *models.Account) error {
	return a.q.CreateAccount(ctx, mysqlstore.CreateAccountParams{
		ID:                account.ID,
		UserID:            account.UserID,
		Provider:          string(account.Provider),
		ProviderAccountID: toNullString(account.ProviderAccountID),
		PasswordHash:      toNullString(account.PasswordHash),
		CreatedAt:         account.CreatedAt,
		UpdatedAt:         account.UpdatedAt,
	})
}

func (a *mysqlAdapter) GetAccountByID(ctx context.Context, id string) (*models.Account, error) {
	acc, err := a.q.GetAccountByID(ctx, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return mysqlAccountToModel(&acc), nil
}

func (a *mysqlAdapter) GetAccountByUserIDAndProvider(ctx context.Context, userID string, provider models.ProviderType) (*models.Account, error) {
	acc, err := a.q.GetAccountByUserIDAndProvider(ctx, mysqlstore.GetAccountByUserIDAndProviderParams{
		UserID:   userID,
		Provider: string(provider),
	})
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return mysqlAccountToModel(&acc), nil
}

func (a *mysqlAdapter) GetAccountByProvider(ctx context.Context, provider models.ProviderType, providerAccountID string) (*models.Account, error) {
	acc, err := a.q.GetAccountByProvider(ctx, mysqlstore.GetAccountByProviderParams{
		Provider:          string(provider),
		ProviderAccountID: toNullString(&providerAccountID),
	})
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return mysqlAccountToModel(&acc), nil
}

func (a *mysqlAdapter) ListAccountsByUserID(ctx context.Context, userID string) ([]*models.Account, error) {
	accounts, err := a.q.ListAccountsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	result := make([]*models.Account, len(accounts))
	for i := range accounts {
		result[i] = mysqlAccountToModel(&accounts[i])
	}
	return result, nil
}

func (a *mysqlAdapter) UpdateAccount(ctx context.Context, account *models.Account) error {
	return a.q.UpdateAccount(ctx, mysqlstore.UpdateAccountParams{
		ID:                account.ID,
		Provider:          string(account.Provider),
		ProviderAccountID: toNullString(account.ProviderAccountID),
		PasswordHash:      toNullString(account.PasswordHash),
		UpdatedAt:         time.Now(),
	})
}

func (a *mysqlAdapter) DeleteAccount(ctx context.Context, id string) error {
	return a.q.DeleteAccount(ctx, id)
}

func (a *mysqlAdapter) DeleteAccountsByUserID(ctx context.Context, userID string) error {
	return a.q.DeleteAccountsByUserID(ctx, userID)
}

// =============================================================================
// Session operations
// =============================================================================

func (a *mysqlAdapter) CreateSession(ctx context.Context, session *models.Session) error {
	return a.q.CreateSession(ctx, mysqlstore.CreateSessionParams{
		ID:             session.ID,
		UserID:         session.UserID,
		TokenHash:      session.TokenHash,
		IpAddress:      toNullString(session.IPAddress),
		UserAgent:      toNullString(session.UserAgent),
		CreatedAt:      session.CreatedAt,
		ExpiresAt:      session.ExpiresAt,
		LastUsed:       session.LastUsed,
		ImpersonatedBy: toNullString(session.ImpersonatedBy),
	})
}

func (a *mysqlAdapter) GetSessionByID(ctx context.Context, id string) (*models.Session, error) {
	sess, err := a.q.GetSessionByID(ctx, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return mysqlSessionToModel(&sess), nil
}

func (a *mysqlAdapter) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*models.Session, error) {
	sess, err := a.q.GetSessionByTokenHash(ctx, tokenHash)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return mysqlSessionToModel(&sess), nil
}

func (a *mysqlAdapter) ListSessionsByUserID(ctx context.Context, userID string) ([]*models.Session, error) {
	sessions, err := a.q.ListSessionsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	result := make([]*models.Session, len(sessions))
	for i := range sessions {
		result[i] = mysqlSessionToModel(&sessions[i])
	}
	return result, nil
}

func (a *mysqlAdapter) UpdateSessionLastUsed(ctx context.Context, id string) error {
	return a.q.UpdateSessionLastUsed(ctx, mysqlstore.UpdateSessionLastUsedParams{
		ID:       id,
		LastUsed: time.Now(),
	})
}

func (a *mysqlAdapter) DeleteSession(ctx context.Context, id string) error {
	return a.q.DeleteSession(ctx, id)
}

func (a *mysqlAdapter) DeleteSessionsByUserID(ctx context.Context, userID string) error {
	return a.q.DeleteSessionsByUserID(ctx, userID)
}

func (a *mysqlAdapter) DeleteExpiredSessions(ctx context.Context) error {
	return a.q.DeleteExpiredSessions(ctx, time.Now())
}

// =============================================================================
// Verification operations
// =============================================================================

func (a *mysqlAdapter) CreateVerification(ctx context.Context, v *models.Verification) error {
	return a.q.CreateVerification(ctx, mysqlstore.CreateVerificationParams{
		ID:         v.ID,
		UserID:     v.UserID,
		TokenHash:  v.TokenHash,
		Type:       string(v.Type),
		Identifier: toNullString(v.Identifier),
		ExpiresAt:  v.ExpiresAt,
		CreatedAt:  v.CreatedAt,
	})
}

func (a *mysqlAdapter) GetVerificationByTokenHash(ctx context.Context, tokenHash string) (*models.Verification, error) {
	v, err := a.q.GetVerificationByTokenHash(ctx, tokenHash)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return mysqlVerificationToModel(&v), nil
}

func (a *mysqlAdapter) DeleteVerification(ctx context.Context, id string) error {
	return a.q.DeleteVerification(ctx, id)
}

func (a *mysqlAdapter) DeleteVerificationsByUserIDAndType(ctx context.Context, userID string, vType models.VerificationType) error {
	return a.q.DeleteVerificationsByUserIDAndType(ctx, mysqlstore.DeleteVerificationsByUserIDAndTypeParams{
		UserID: userID,
		Type:   string(vType),
	})
}

func (a *mysqlAdapter) DeleteExpiredVerifications(ctx context.Context) error {
	return a.q.DeleteExpiredVerifications(ctx, time.Now())
}

// =============================================================================
// Admin operations
// =============================================================================

func (a *mysqlAdapter) AdminListUsers(ctx context.Context, opts AdminListUsersOptions) ([]*models.User, error) {
	var users []mysqlstore.User
	var err error

	switch {
	case opts.Query != "" && opts.Role != "":
		query := "%" + opts.Query + "%"
		users, err = a.q.ListUsersWithQueryAndRole(ctx, mysqlstore.ListUsersWithQueryAndRoleParams{
			Name:   query,
			Email:  query,
			Role:   opts.Role,
			Offset: int32(opts.Offset),
			Limit:  int32(opts.Limit),
		})
	case opts.Query != "":
		query := "%" + opts.Query + "%"
		users, err = a.q.ListUsersWithQuery(ctx, mysqlstore.ListUsersWithQueryParams{
			Name:   query,
			Email:  query,
			Offset: int32(opts.Offset),
			Limit:  int32(opts.Limit),
		})
	case opts.Role != "":
		users, err = a.q.ListUsersWithRole(ctx, mysqlstore.ListUsersWithRoleParams{
			Role:   opts.Role,
			Offset: int32(opts.Offset),
			Limit:  int32(opts.Limit),
		})
	default:
		users, err = a.q.ListAllUsers(ctx, mysqlstore.ListAllUsersParams{
			Offset: int32(opts.Offset),
			Limit:  int32(opts.Limit),
		})
	}

	if err != nil {
		return nil, err
	}

	result := make([]*models.User, len(users))
	for i := range users {
		result[i] = mysqlUserToModel(&users[i])
	}
	return result, nil
}

func (a *mysqlAdapter) AdminCountUsers(ctx context.Context, opts AdminListUsersOptions) (int64, error) {
	switch {
	case opts.Query != "" && opts.Role != "":
		query := "%" + opts.Query + "%"
		return a.q.CountUsersWithQueryAndRole(ctx, mysqlstore.CountUsersWithQueryAndRoleParams{
			Name:  query,
			Email: query,
			Role:  opts.Role,
		})
	case opts.Query != "":
		query := "%" + opts.Query + "%"
		return a.q.CountUsersWithQuery(ctx, mysqlstore.CountUsersWithQueryParams{
			Name:  query,
			Email: query,
		})
	case opts.Role != "":
		return a.q.CountUsersWithRole(ctx, opts.Role)
	default:
		return a.q.CountAllUsers(ctx)
	}
}

func (a *mysqlAdapter) AdminBanUser(ctx context.Context, userID string, reason *string) error {
	var banReason sql.NullString
	if reason != nil {
		banReason = sql.NullString{String: *reason, Valid: true}
	}
	return a.q.BanUser(ctx, mysqlstore.BanUserParams{
		ID:        userID,
		BanReason: banReason,
		UpdatedAt: time.Now(),
	})
}

func (a *mysqlAdapter) AdminUnbanUser(ctx context.Context, userID string) error {
	return a.q.UnbanUser(ctx, mysqlstore.UnbanUserParams{
		ID:        userID,
		UpdatedAt: time.Now(),
	})
}

func (a *mysqlAdapter) AdminSetUserRole(ctx context.Context, userID, role string) error {
	return a.q.SetUserRole(ctx, mysqlstore.SetUserRoleParams{
		ID:        userID,
		Role:      role,
		UpdatedAt: time.Now(),
	})
}

func (a *mysqlAdapter) AdminDeleteUserCascade(ctx context.Context, userID string) error {
	// Delete sessions first
	if err := a.q.DeleteSessionsByUserID(ctx, userID); err != nil {
		return err
	}
	// Delete accounts
	if err := a.q.DeleteAccountsByUserID(ctx, userID); err != nil {
		return err
	}
	// Delete user
	return a.q.DeleteUser(ctx, userID)
}

// =============================================================================
// Anonymous operations
// =============================================================================

func (a *mysqlAdapter) SetAnonymousFlag(ctx context.Context, userID string, isAnonymous bool) error {
	return a.q.SetAnonymousFlag(ctx, mysqlstore.SetAnonymousFlagParams{
		ID:          userID,
		IsAnonymous: isAnonymous,
		UpdatedAt:   time.Now(),
	})
}

func (a *mysqlAdapter) DeleteStaleAnonymousUsers(ctx context.Context, cutoff time.Time) (int64, error) {
	return a.q.DeleteStaleAnonymousUsers(ctx, cutoff)
}

func (a *mysqlAdapter) GetUserWithAnonymousStatus(ctx context.Context, userID string) (*AnonymousUser, error) {
	row, err := a.q.GetUserWithAnonymousStatus(ctx, userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &AnonymousUser{
		ID:            row.ID,
		Email:         row.Email,
		EmailVerified: row.EmailVerified,
		Name:          row.Name,
		Image:         fromNullString(row.Image),
		Role:          row.Role,
		Banned:        row.Banned,
		IsAnonymous:   row.IsAnonymous,
		CreatedAt:     row.CreatedAt,
		UpdatedAt:     row.UpdatedAt,
	}, nil
}

// Ensure pgAdapter implements Querier
var _ Querier = (*pgAdapter)(nil)
