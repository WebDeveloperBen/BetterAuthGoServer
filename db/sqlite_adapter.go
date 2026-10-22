package db

import (
	"context"
	"database/sql"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/db/sqlitestore"
)

// sqliteAdapter implements Querier using SQLite-specific sqlc queries.
type sqliteAdapter struct {
	q *sqlitestore.Queries
}

// newSqliteAdapter creates a new SQLite adapter.
func newSqliteAdapter(db DBTX) *sqliteAdapter {
	return &sqliteAdapter{q: sqlitestore.New(db)}
}

// =============================================================================
// User operations
// =============================================================================

func (a *sqliteAdapter) CreateUser(ctx context.Context, user *models.User) error {
	return a.q.CreateUser(ctx, sqlitestore.CreateUserParams{
		ID:            user.ID,
		Email:         user.Email,
		EmailVerified: boolToInt(user.EmailVerified),
		Name:          user.Name,
		Image:         toNullString(user.Image),
		Banned:        boolToInt(user.Banned),
		BannedAt:      toNullString(timeToString(user.BannedAt)),
		BanReason:     toNullString(user.BanReason),
		Role:          user.Role,
		CreatedAt:     user.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     user.UpdatedAt.Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	u, err := a.q.GetUserByID(ctx, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return sqliteUserToModel(&u), nil
}
func (a *sqliteAdapter) GetUsersByIDs(ctx context.Context, userIDs []string) ([]*models.User, error) {
	if len(userIDs) == 0 {
		return []*models.User{}, nil
	}
	users, err := a.q.GetUsersByIDs(ctx, userIDs)
	if err != nil {
		return nil, err
	}
	result := make([]*models.User, len(users))
	for i := range users {
		result[i] = sqliteUserToModel(&users[i])
	}
	return result, nil
}

func (a *sqliteAdapter) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	u, err := a.q.GetUserByEmail(ctx, email)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return sqliteUserToModel(&u), nil
}

func (a *sqliteAdapter) UpdateUser(ctx context.Context, user *models.User) error {
	return a.q.UpdateUser(ctx, sqlitestore.UpdateUserParams{
		ID:            user.ID,
		Email:         user.Email,
		EmailVerified: boolToInt(user.EmailVerified),
		Name:          user.Name,
		Image:         toNullString(user.Image),
		Banned:        boolToInt(user.Banned),
		BannedAt:      toNullString(timeToString(user.BannedAt)),
		BanReason:     toNullString(user.BanReason),
		Role:          user.Role,
		UpdatedAt:     time.Now().Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) SetEmailVerified(ctx context.Context, userID string, verified bool) error {
	return a.q.SetEmailVerified(ctx, sqlitestore.SetEmailVerifiedParams{
		ID:            userID,
		EmailVerified: boolToInt(verified),
		UpdatedAt:     time.Now().Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) DeleteUser(ctx context.Context, id string) error {
	return a.q.DeleteUser(ctx, id)
}

func (a *sqliteAdapter) LockUser(ctx context.Context, id string) error {
	n, err := a.q.LockUser(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return models.ErrUserNotFound
	}
	return nil
}

// =============================================================================
// Account operations
// =============================================================================

func (a *sqliteAdapter) CreateAccount(ctx context.Context, account *models.Account) error {
	return a.q.CreateAccount(ctx, sqlitestore.CreateAccountParams{
		ID:                account.ID,
		UserID:            account.UserID,
		Provider:          string(account.Provider),
		ProviderAccountID: toNullString(account.ProviderAccountID),
		PasswordHash:      toNullString(account.PasswordHash),
		CreatedAt:         account.CreatedAt.Format(time.RFC3339),
		UpdatedAt:         account.UpdatedAt.Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) GetAccountByID(ctx context.Context, id string) (*models.Account, error) {
	acc, err := a.q.GetAccountByID(ctx, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return sqliteAccountToModel(&acc), nil
}

func (a *sqliteAdapter) GetAccountByUserIDAndProvider(ctx context.Context, userID string, provider models.ProviderType) (*models.Account, error) {
	acc, err := a.q.GetAccountByUserIDAndProvider(ctx, sqlitestore.GetAccountByUserIDAndProviderParams{
		UserID:   userID,
		Provider: string(provider),
	})
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return sqliteAccountToModel(&acc), nil
}

func (a *sqliteAdapter) GetAccountByProvider(ctx context.Context, provider models.ProviderType, providerAccountID string) (*models.Account, error) {
	acc, err := a.q.GetAccountByProvider(ctx, sqlitestore.GetAccountByProviderParams{
		Provider:          string(provider),
		ProviderAccountID: toNullString(&providerAccountID),
	})
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return sqliteAccountToModel(&acc), nil
}

func (a *sqliteAdapter) ListAccountsByUserID(ctx context.Context, userID string) ([]*models.Account, error) {
	accounts, err := a.q.ListAccountsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	result := make([]*models.Account, len(accounts))
	for i := range accounts {
		result[i] = sqliteAccountToModel(&accounts[i])
	}
	return result, nil
}
func (a *sqliteAdapter) ListAccountsByUserIDs(ctx context.Context, userIDs []string) ([]*models.Account, error) {
	if len(userIDs) == 0 {
		return []*models.Account{}, nil
	}
	accounts, err := a.q.ListAccountsByUserIDs(ctx, userIDs)
	if err != nil {
		return nil, err
	}
	result := make([]*models.Account, len(accounts))
	for i := range accounts {
		result[i] = sqliteAccountToModel(&accounts[i])
	}
	return result, nil
}

func (a *sqliteAdapter) UpdateAccount(ctx context.Context, account *models.Account) error {
	return a.q.UpdateAccount(ctx, sqlitestore.UpdateAccountParams{
		ID:                account.ID,
		Provider:          string(account.Provider),
		ProviderAccountID: toNullString(account.ProviderAccountID),
		PasswordHash:      toNullString(account.PasswordHash),
		UpdatedAt:         time.Now().Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) DeleteAccount(ctx context.Context, id string) error {
	return a.q.DeleteAccount(ctx, id)
}

func (a *sqliteAdapter) DeleteAccountsByUserID(ctx context.Context, userID string) error {
	return a.q.DeleteAccountsByUserID(ctx, userID)
}

// =============================================================================
// Session operations
// =============================================================================

func (a *sqliteAdapter) CreateSession(ctx context.Context, session *models.Session) error {
	return a.q.CreateSession(ctx, sqlitestore.CreateSessionParams{
		ID:             session.ID,
		UserID:         session.UserID,
		TokenHash:      session.TokenHash,
		IpAddress:      toNullString(session.IPAddress),
		UserAgent:      toNullString(session.UserAgent),
		CreatedAt:      session.CreatedAt.Format(time.RFC3339),
		ExpiresAt:      session.ExpiresAt.Format(time.RFC3339),
		LastUsed:       session.LastUsed.Format(time.RFC3339),
		ImpersonatedBy: toNullString(session.ImpersonatedBy),
	})
}

func (a *sqliteAdapter) GetSessionByID(ctx context.Context, id string) (*models.Session, error) {
	sess, err := a.q.GetSessionByID(ctx, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return sqliteSessionToModel(&sess), nil
}

func (a *sqliteAdapter) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*models.Session, error) {
	sess, err := a.q.GetSessionByTokenHash(ctx, tokenHash)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return sqliteSessionToModel(&sess), nil
}

func (a *sqliteAdapter) ListSessionsByUserID(ctx context.Context, userID string) ([]*models.Session, error) {
	sessions, err := a.q.ListSessionsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	result := make([]*models.Session, len(sessions))
	for i := range sessions {
		result[i] = sqliteSessionToModel(&sessions[i])
	}
	return result, nil
}

func (a *sqliteAdapter) UpdateSessionLastUsed(ctx context.Context, id string) error {
	return a.q.UpdateSessionLastUsed(ctx, sqlitestore.UpdateSessionLastUsedParams{
		ID:       id,
		LastUsed: time.Now().Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) DeleteSession(ctx context.Context, id string) error {
	return a.q.DeleteSession(ctx, id)
}

func (a *sqliteAdapter) DeleteSessionsByUserID(ctx context.Context, userID string) error {
	return a.q.DeleteSessionsByUserID(ctx, userID)
}

func (a *sqliteAdapter) DeleteExpiredSessions(ctx context.Context) error {
	return a.q.DeleteExpiredSessions(ctx, time.Now().Format(time.RFC3339))
}

// =============================================================================
// Verification operations
// =============================================================================

func (a *sqliteAdapter) CreateVerification(ctx context.Context, v *models.Verification) error {
	return a.q.CreateVerification(ctx, sqlitestore.CreateVerificationParams{
		ID:         v.ID,
		UserID:     v.UserID,
		TokenHash:  v.TokenHash,
		Type:       string(v.Type),
		Identifier: toNullString(v.Identifier),
		ExpiresAt:  v.ExpiresAt.Format(time.RFC3339),
		CreatedAt:  v.CreatedAt.Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) GetVerificationByTokenHash(ctx context.Context, tokenHash string) (*models.Verification, error) {
	v, err := a.q.GetVerificationByTokenHash(ctx, tokenHash)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return sqliteVerificationToModel(&v), nil
}

func (a *sqliteAdapter) DeleteVerification(ctx context.Context, id string) error {
	return a.q.DeleteVerification(ctx, id)
}

func (a *sqliteAdapter) DeleteVerificationsByUserIDAndType(ctx context.Context, userID string, vType models.VerificationType) error {
	return a.q.DeleteVerificationsByUserIDAndType(ctx, sqlitestore.DeleteVerificationsByUserIDAndTypeParams{
		UserID: userID,
		Type:   string(vType),
	})
}

func (a *sqliteAdapter) DeleteExpiredVerifications(ctx context.Context) error {
	return a.q.DeleteExpiredVerifications(ctx, time.Now().Format(time.RFC3339))
}

// =============================================================================
// Admin operations
// =============================================================================

func (a *sqliteAdapter) AdminListUsers(ctx context.Context, opts AdminListUsersOptions) ([]*models.User, error) {
	var users []sqlitestore.User
	var err error

	switch {
	case opts.Query != "" && opts.Role != "":
		users, err = a.q.ListUsersWithQueryAndRole(ctx, sqlitestore.ListUsersWithQueryAndRoleParams{
			Column1: sql.NullString{String: opts.Query, Valid: true},
			Column2: sql.NullString{String: opts.Query, Valid: true},
			Role:    opts.Role,
			Limit:   int64(opts.Limit),
			Offset:  int64(opts.Offset),
		})
	case opts.Query != "":
		users, err = a.q.ListUsersWithQuery(ctx, sqlitestore.ListUsersWithQueryParams{
			Column1: sql.NullString{String: opts.Query, Valid: true},
			Column2: sql.NullString{String: opts.Query, Valid: true},
			Limit:   int64(opts.Limit),
			Offset:  int64(opts.Offset),
		})
	case opts.Role != "":
		users, err = a.q.ListUsersWithRole(ctx, sqlitestore.ListUsersWithRoleParams{
			Role:   opts.Role,
			Limit:  int64(opts.Limit),
			Offset: int64(opts.Offset),
		})
	default:
		users, err = a.q.ListAllUsers(ctx, sqlitestore.ListAllUsersParams{
			Limit:  int64(opts.Limit),
			Offset: int64(opts.Offset),
		})
	}

	if err != nil {
		return nil, err
	}

	result := make([]*models.User, len(users))
	for i := range users {
		result[i] = sqliteUserToModel(&users[i])
	}
	return result, nil
}

func (a *sqliteAdapter) AdminCountUsers(ctx context.Context, opts AdminListUsersOptions) (int64, error) {
	switch {
	case opts.Query != "" && opts.Role != "":
		return a.q.CountUsersWithQueryAndRole(ctx, sqlitestore.CountUsersWithQueryAndRoleParams{
			Column1: sql.NullString{String: opts.Query, Valid: true},
			Column2: sql.NullString{String: opts.Query, Valid: true},
			Role:    opts.Role,
		})
	case opts.Query != "":
		return a.q.CountUsersWithQuery(ctx, sqlitestore.CountUsersWithQueryParams{
			Column1: sql.NullString{String: opts.Query, Valid: true},
			Column2: sql.NullString{String: opts.Query, Valid: true},
		})
	case opts.Role != "":
		return a.q.CountUsersWithRole(ctx, opts.Role)
	default:
		return a.q.CountAllUsers(ctx)
	}
}

func (a *sqliteAdapter) AdminBanUser(ctx context.Context, userID string, reason *string) error {
	var banReason sql.NullString
	if reason != nil {
		banReason = sql.NullString{String: *reason, Valid: true}
	}
	return a.q.BanUser(ctx, sqlitestore.BanUserParams{
		BanReason: banReason,
		UpdatedAt: time.Now().Format(time.RFC3339),
		ID:        userID,
	})
}

func (a *sqliteAdapter) AdminUnbanUser(ctx context.Context, userID string) error {
	return a.q.UnbanUser(ctx, sqlitestore.UnbanUserParams{
		UpdatedAt: time.Now().Format(time.RFC3339),
		ID:        userID,
	})
}

func (a *sqliteAdapter) AdminSetUserRole(ctx context.Context, userID, role string) error {
	return a.q.SetUserRole(ctx, sqlitestore.SetUserRoleParams{
		Role:      role,
		UpdatedAt: time.Now().Format(time.RFC3339),
		ID:        userID,
	})
}

func (a *sqliteAdapter) AdminDeleteUserCascade(ctx context.Context, userID string) error {
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

func (a *sqliteAdapter) SetAnonymousFlag(ctx context.Context, userID string, isAnonymous bool) error {
	var isAnonInt int64
	if isAnonymous {
		isAnonInt = 1
	}
	return a.q.SetAnonymousFlag(ctx, sqlitestore.SetAnonymousFlagParams{
		IsAnonymous: isAnonInt,
		UpdatedAt:   time.Now().Format(time.RFC3339),
		ID:          userID,
	})
}

func (a *sqliteAdapter) DeleteStaleAnonymousUsers(ctx context.Context, cutoff time.Time) (int64, error) {
	return a.q.DeleteStaleAnonymousUsers(ctx, cutoff.Format(time.RFC3339))
}

func (a *sqliteAdapter) GetUserWithAnonymousStatus(ctx context.Context, userID string) (*AnonymousUser, error) {
	row, err := a.q.GetUserWithAnonymousStatus(ctx, userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	createdAt, _ := time.Parse(time.RFC3339, row.CreatedAt)
	updatedAt, _ := time.Parse(time.RFC3339, row.UpdatedAt)

	return &AnonymousUser{
		ID:            row.ID,
		Email:         row.Email,
		EmailVerified: row.EmailVerified != 0,
		Name:          row.Name,
		Image:         fromNullString(row.Image),
		Role:          row.Role,
		Banned:        row.Banned != 0,
		IsAnonymous:   row.IsAnonymous != 0,
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
	}, nil
}

// Ensure sqliteAdapter implements Querier
var _ Querier = (*sqliteAdapter)(nil)
