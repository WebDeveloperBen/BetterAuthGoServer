package db

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/db/pgstore"
)

// pgAdapter implements Querier using PostgreSQL-specific sqlc queries.
type pgAdapter struct {
	db DBTX
	q  *pgstore.Queries
}

// newPgAdapter creates a new PostgreSQL adapter.
func newPgAdapter(db DBTX) *pgAdapter {
	return &pgAdapter{db: db, q: pgstore.New(db)}
}

func postgresIDPlaceholders(ids []string) (string, []any) {
	var placeholders strings.Builder
	placeholders.Grow(len(ids) * 4)
	args := make([]any, len(ids))
	for i, id := range ids {
		if i > 0 {
			placeholders.WriteString(", ")
		}
		placeholders.WriteByte('$')
		placeholders.WriteString(strconv.Itoa(i + 1))
		args[i] = id
	}
	return placeholders.String(), args
}

// =============================================================================
// User operations
// =============================================================================

func (a *pgAdapter) CreateUser(ctx context.Context, user *models.User) error {
	return a.q.CreateUser(ctx, pgstore.CreateUserParams{
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

func (a *pgAdapter) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	u, err := a.q.GetUserByID(ctx, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return pgUserToModel(&u), nil
}
func (a *pgAdapter) GetUsersByIDs(ctx context.Context, userIDs []string) ([]*models.User, error) {
	if len(userIDs) == 0 {
		return []*models.User{}, nil
	}
	placeholders, args := postgresIDPlaceholders(userIDs)
	query := "SELECT id, email, email_verified, name, image, banned, banned_at, ban_reason, role, is_anonymous, created_at, updated_at FROM users WHERE id IN (" + placeholders + ")"
	rows, err := a.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := make([]*models.User, 0)
	for rows.Next() {
		var user pgstore.User
		if err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.EmailVerified,
			&user.Name,
			&user.Image,
			&user.Banned,
			&user.BannedAt,
			&user.BanReason,
			&user.Role,
			&user.IsAnonymous,
			&user.CreatedAt,
			&user.UpdatedAt,
		); err != nil {
			return nil, err
		}
		users = append(users, pgUserToModel(&user))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

func (a *pgAdapter) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	u, err := a.q.GetUserByEmail(ctx, email)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return pgUserToModel(&u), nil
}

func (a *pgAdapter) UpdateUser(ctx context.Context, user *models.User) error {
	return a.q.UpdateUser(ctx, pgstore.UpdateUserParams{
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

func (a *pgAdapter) SetEmailVerified(ctx context.Context, userID string, verified bool) error {
	return a.q.SetEmailVerified(ctx, pgstore.SetEmailVerifiedParams{
		ID:            userID,
		EmailVerified: verified,
		UpdatedAt:     time.Now(),
	})
}

func (a *pgAdapter) DeleteUser(ctx context.Context, id string) error {
	return a.q.DeleteUser(ctx, id)
}

func (a *pgAdapter) LockUser(ctx context.Context, id string) error {
	_, err := a.q.LockUser(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return models.ErrUserNotFound
	}
	return err
}

// =============================================================================
// Account operations
// =============================================================================

func (a *pgAdapter) CreateAccount(ctx context.Context, account *models.Account) error {
	return a.q.CreateAccount(ctx, pgstore.CreateAccountParams{
		ID:                account.ID,
		UserID:            account.UserID,
		Provider:          string(account.Provider),
		ProviderAccountID: toNullString(account.ProviderAccountID),
		PasswordHash:      toNullString(account.PasswordHash),
		CreatedAt:         account.CreatedAt,
		UpdatedAt:         account.UpdatedAt,
	})
}

func (a *pgAdapter) GetAccountByID(ctx context.Context, id string) (*models.Account, error) {
	acc, err := a.q.GetAccountByID(ctx, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return pgAccountToModel(&acc), nil
}

func (a *pgAdapter) GetAccountByUserIDAndProvider(ctx context.Context, userID string, provider models.ProviderType) (*models.Account, error) {
	acc, err := a.q.GetAccountByUserIDAndProvider(ctx, pgstore.GetAccountByUserIDAndProviderParams{
		UserID:   userID,
		Provider: string(provider),
	})
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return pgAccountToModel(&acc), nil
}

func (a *pgAdapter) GetAccountByProvider(ctx context.Context, provider models.ProviderType, providerAccountID string) (*models.Account, error) {
	acc, err := a.q.GetAccountByProvider(ctx, pgstore.GetAccountByProviderParams{
		Provider:          string(provider),
		ProviderAccountID: toNullString(&providerAccountID),
	})
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return pgAccountToModel(&acc), nil
}

func (a *pgAdapter) ListAccountsByUserID(ctx context.Context, userID string) ([]*models.Account, error) {
	accounts, err := a.q.ListAccountsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	result := make([]*models.Account, len(accounts))
	for i := range accounts {
		result[i] = pgAccountToModel(&accounts[i])
	}
	return result, nil
}
func (a *pgAdapter) ListAccountsByUserIDs(ctx context.Context, userIDs []string) ([]*models.Account, error) {
	if len(userIDs) == 0 {
		return []*models.Account{}, nil
	}
	placeholders, args := postgresIDPlaceholders(userIDs)
	query := "SELECT id, user_id, provider, provider_account_id, password_hash, created_at, updated_at FROM accounts WHERE user_id IN (" + placeholders + ")"
	rows, err := a.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	accounts := make([]*models.Account, 0)
	for rows.Next() {
		var account pgstore.Account
		if err := rows.Scan(
			&account.ID,
			&account.UserID,
			&account.Provider,
			&account.ProviderAccountID,
			&account.PasswordHash,
			&account.CreatedAt,
			&account.UpdatedAt,
		); err != nil {
			return nil, err
		}
		accounts = append(accounts, pgAccountToModel(&account))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return accounts, nil
}

func (a *pgAdapter) UpdateAccount(ctx context.Context, account *models.Account) error {
	return a.q.UpdateAccount(ctx, pgstore.UpdateAccountParams{
		ID:                account.ID,
		Provider:          string(account.Provider),
		ProviderAccountID: toNullString(account.ProviderAccountID),
		PasswordHash:      toNullString(account.PasswordHash),
		UpdatedAt:         time.Now(),
	})
}

func (a *pgAdapter) DeleteAccount(ctx context.Context, id string) error {
	return a.q.DeleteAccount(ctx, id)
}

func (a *pgAdapter) DeleteAccountsByUserID(ctx context.Context, userID string) error {
	return a.q.DeleteAccountsByUserID(ctx, userID)
}

// =============================================================================
// Session operations
// =============================================================================

func (a *pgAdapter) CreateSession(ctx context.Context, session *models.Session) error {
	return a.q.CreateSession(ctx, pgstore.CreateSessionParams{
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

func (a *pgAdapter) GetSessionByID(ctx context.Context, id string) (*models.Session, error) {
	sess, err := a.q.GetSessionByID(ctx, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return pgSessionToModel(&sess), nil
}

func (a *pgAdapter) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*models.Session, error) {
	sess, err := a.q.GetSessionByTokenHash(ctx, tokenHash)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return pgSessionToModel(&sess), nil
}

func (a *pgAdapter) ListSessionsByUserID(ctx context.Context, userID string) ([]*models.Session, error) {
	sessions, err := a.q.ListSessionsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	result := make([]*models.Session, len(sessions))
	for i := range sessions {
		result[i] = pgSessionToModel(&sessions[i])
	}
	return result, nil
}

func (a *pgAdapter) UpdateSessionLastUsed(ctx context.Context, id string) error {
	return a.q.UpdateSessionLastUsed(ctx, pgstore.UpdateSessionLastUsedParams{
		ID:       id,
		LastUsed: time.Now(),
	})
}

func (a *pgAdapter) DeleteSession(ctx context.Context, id string) error {
	return a.q.DeleteSession(ctx, id)
}

func (a *pgAdapter) DeleteSessionsByUserID(ctx context.Context, userID string) error {
	return a.q.DeleteSessionsByUserID(ctx, userID)
}

func (a *pgAdapter) DeleteExpiredSessions(ctx context.Context) error {
	return a.q.DeleteExpiredSessions(ctx, time.Now())
}

// =============================================================================
// Verification operations
// =============================================================================

func (a *pgAdapter) CreateVerification(ctx context.Context, v *models.Verification) error {
	return a.q.CreateVerification(ctx, pgstore.CreateVerificationParams{
		ID:         v.ID,
		UserID:     v.UserID,
		TokenHash:  v.TokenHash,
		Type:       string(v.Type),
		Identifier: toNullString(v.Identifier),
		ExpiresAt:  v.ExpiresAt,
		CreatedAt:  v.CreatedAt,
	})
}

func (a *pgAdapter) GetVerificationByTokenHash(ctx context.Context, tokenHash string) (*models.Verification, error) {
	v, err := a.q.GetVerificationByTokenHash(ctx, tokenHash)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return pgVerificationToModel(&v), nil
}

func (a *pgAdapter) DeleteVerification(ctx context.Context, id string) error {
	return a.q.DeleteVerification(ctx, id)
}

func (a *pgAdapter) DeleteVerificationsByUserIDAndType(ctx context.Context, userID string, vType models.VerificationType) error {
	return a.q.DeleteVerificationsByUserIDAndType(ctx, pgstore.DeleteVerificationsByUserIDAndTypeParams{
		UserID: userID,
		Type:   string(vType),
	})
}

func (a *pgAdapter) DeleteExpiredVerifications(ctx context.Context) error {
	return a.q.DeleteExpiredVerifications(ctx, time.Now())
}

// =============================================================================
// Admin operations
// =============================================================================

func (a *pgAdapter) AdminListUsers(ctx context.Context, opts AdminListUsersOptions) ([]*models.User, error) {
	var users []pgstore.User
	var err error

	switch {
	case opts.Query != "" && opts.Role != "":
		users, err = a.q.ListUsersWithQueryAndRole(ctx, pgstore.ListUsersWithQueryAndRoleParams{
			Column1: sql.NullString{String: opts.Query, Valid: true},
			Role:    opts.Role,
			Offset:  int32(opts.Offset),
			Limit:   int32(opts.Limit),
		})
	case opts.Query != "":
		users, err = a.q.ListUsersWithQuery(ctx, pgstore.ListUsersWithQueryParams{
			Column1: sql.NullString{String: opts.Query, Valid: true},
			Offset:  int32(opts.Offset),
			Limit:   int32(opts.Limit),
		})
	case opts.Role != "":
		users, err = a.q.ListUsersWithRole(ctx, pgstore.ListUsersWithRoleParams{
			Role:   opts.Role,
			Offset: int32(opts.Offset),
			Limit:  int32(opts.Limit),
		})
	default:
		users, err = a.q.ListAllUsers(ctx, pgstore.ListAllUsersParams{
			Offset: int32(opts.Offset),
			Limit:  int32(opts.Limit),
		})
	}

	if err != nil {
		return nil, err
	}

	result := make([]*models.User, len(users))
	for i := range users {
		result[i] = pgUserToModel(&users[i])
	}
	return result, nil
}

func (a *pgAdapter) AdminCountUsers(ctx context.Context, opts AdminListUsersOptions) (int64, error) {
	switch {
	case opts.Query != "" && opts.Role != "":
		return a.q.CountUsersWithQueryAndRole(ctx, pgstore.CountUsersWithQueryAndRoleParams{
			Column1: sql.NullString{String: opts.Query, Valid: true},
			Role:    opts.Role,
		})
	case opts.Query != "":
		return a.q.CountUsersWithQuery(ctx, sql.NullString{String: opts.Query, Valid: true})
	case opts.Role != "":
		return a.q.CountUsersWithRole(ctx, opts.Role)
	default:
		return a.q.CountAllUsers(ctx)
	}
}

func (a *pgAdapter) AdminBanUser(ctx context.Context, userID string, reason *string) error {
	var banReason sql.NullString
	if reason != nil {
		banReason = sql.NullString{String: *reason, Valid: true}
	}
	return a.q.BanUser(ctx, pgstore.BanUserParams{
		ID:        userID,
		BanReason: banReason,
		UpdatedAt: time.Now(),
	})
}

func (a *pgAdapter) AdminUnbanUser(ctx context.Context, userID string) error {
	return a.q.UnbanUser(ctx, pgstore.UnbanUserParams{
		ID:        userID,
		UpdatedAt: time.Now(),
	})
}

func (a *pgAdapter) AdminSetUserRole(ctx context.Context, userID, role string) error {
	return a.q.SetUserRole(ctx, pgstore.SetUserRoleParams{
		ID:        userID,
		Role:      role,
		UpdatedAt: time.Now(),
	})
}

func (a *pgAdapter) AdminDeleteUserCascade(ctx context.Context, userID string) error {
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

func (a *pgAdapter) SetAnonymousFlag(ctx context.Context, userID string, isAnonymous bool) error {
	return a.q.SetAnonymousFlag(ctx, pgstore.SetAnonymousFlagParams{
		ID:          userID,
		IsAnonymous: isAnonymous,
		UpdatedAt:   time.Now(),
	})
}

func (a *pgAdapter) DeleteStaleAnonymousUsers(ctx context.Context, cutoff time.Time) (int64, error) {
	return a.q.DeleteStaleAnonymousUsers(ctx, cutoff)
}

func (a *pgAdapter) GetUserWithAnonymousStatus(ctx context.Context, userID string) (*AnonymousUser, error) {
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
