package db

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/db/pgstore"
)

// pgAdapter implements Querier using PostgreSQL-specific sqlc queries.
type pgAdapter struct {
	q *pgstore.Queries
}

// newPgAdapter creates a new PostgreSQL adapter.
func newPgAdapter(db DBTX) *pgAdapter {
	return &pgAdapter{q: pgstore.New(db)}
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
// OTP operations
// =============================================================================

func (a *pgAdapter) CreateOTPToken(ctx context.Context, token *OTPToken) error {
	return a.q.CreateOTPToken(ctx, pgstore.CreateOTPTokenParams{
		ID:         token.ID,
		UserID:     token.UserID,
		TokenHash:  token.TokenHash,
		Type:       token.Type,
		Identifier: toNullString(token.Identifier),
		ExpiresAt:  token.ExpiresAt,
		CreatedAt:  token.CreatedAt,
	})
}

func (a *pgAdapter) GetOTPTokenByHash(ctx context.Context, tokenHash string) (*OTPToken, error) {
	t, err := a.q.GetOTPTokenByTokenHash(ctx, tokenHash)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &OTPToken{
		ID:         t.ID,
		UserID:     t.UserID,
		TokenHash:  t.TokenHash,
		Type:       t.Type,
		Identifier: fromNullString(t.Identifier),
		ExpiresAt:  t.ExpiresAt,
		CreatedAt:  t.CreatedAt,
	}, nil
}

func (a *pgAdapter) DeleteOTPToken(ctx context.Context, id string) error {
	return a.q.DeleteOTPToken(ctx, id)
}

func (a *pgAdapter) DeleteOTPTokensByUserAndType(ctx context.Context, userID, tokenType string) error {
	return a.q.DeleteOTPTokensByUserAndType(ctx, pgstore.DeleteOTPTokensByUserAndTypeParams{
		UserID: userID,
		Type:   tokenType,
	})
}

func (a *pgAdapter) DeleteExpiredOTPTokens(ctx context.Context) error {
	return a.q.DeleteExpiredOTPTokens(ctx, time.Now())
}

// =============================================================================
// JWT operations
// =============================================================================

func (a *pgAdapter) RevokeJWTToken(ctx context.Context, jti string, expiresAt time.Time) error {
	return a.q.RevokeJWTToken(ctx, pgstore.RevokeJWTTokenParams{
		ID:        jti,
		ExpiresAt: expiresAt,
	})
}

func (a *pgAdapter) IsJWTTokenRevoked(ctx context.Context, jti string) (bool, error) {
	return a.q.IsJWTTokenRevoked(ctx, jti)
}

func (a *pgAdapter) DeleteExpiredRevokedTokens(ctx context.Context) error {
	return a.q.DeleteExpiredRevokedTokens(ctx, time.Now())
}

// =============================================================================
// OAuth State operations
// =============================================================================

func (a *pgAdapter) CreateOAuthState(ctx context.Context, state *OAuthState) error {
	return a.q.CreateOAuthState(ctx, pgstore.CreateOAuthStateParams{
		State:      state.State,
		Provider:   state.Provider,
		Verifier:   toNullString(state.Verifier),
		RedirectTo: toNullString(state.RedirectTo),
		ExpiresAt:  state.ExpiresAt,
		CreatedAt:  state.CreatedAt,
	})
}

func (a *pgAdapter) GetOAuthState(ctx context.Context, state string) (*OAuthState, error) {
	s, err := a.q.GetOAuthState(ctx, state)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &OAuthState{
		State:      s.State,
		Provider:   s.Provider,
		Verifier:   fromNullString(s.Verifier),
		RedirectTo: fromNullString(s.RedirectTo),
		ExpiresAt:  s.ExpiresAt,
		CreatedAt:  s.CreatedAt,
	}, nil
}

func (a *pgAdapter) DeleteOAuthState(ctx context.Context, state string) error {
	return a.q.DeleteOAuthState(ctx, state)
}

func (a *pgAdapter) DeleteExpiredOAuthStates(ctx context.Context) error {
	return a.q.DeleteExpiredOAuthStates(ctx, time.Now())
}

// =============================================================================
// OAuth Account operations
// =============================================================================

func (a *pgAdapter) CreateOAuthAccount(ctx context.Context, account *OAuthAccount) error {
	return a.q.CreateOAuthAccount(ctx, pgstore.CreateOAuthAccountParams{
		ID:                   account.ID,
		UserID:               account.UserID,
		Provider:             account.Provider,
		ProviderAccountID:    account.ProviderAccountID,
		AccessToken:          toNullString(account.AccessToken),
		RefreshToken:         toNullString(account.RefreshToken),
		AccessTokenExpiresAt: toNullTime(account.AccessTokenExpiresAt),
		CreatedAt:            account.CreatedAt,
		UpdatedAt:            account.UpdatedAt,
	})
}

func (a *pgAdapter) GetOAuthAccountByProvider(ctx context.Context, provider, providerAccountID string) (*OAuthAccount, error) {
	acc, err := a.q.GetOAuthAccountByProvider(ctx, pgstore.GetOAuthAccountByProviderParams{
		Provider:          provider,
		ProviderAccountID: providerAccountID,
	})
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return pgOAuthAccountToModel(&acc), nil
}

func (a *pgAdapter) GetOAuthAccountsByUserID(ctx context.Context, userID string) ([]*OAuthAccount, error) {
	accounts, err := a.q.GetOAuthAccountsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	result := make([]*OAuthAccount, len(accounts))
	for i := range accounts {
		result[i] = pgOAuthAccountToModel(&accounts[i])
	}
	return result, nil
}

func (a *pgAdapter) UpdateOAuthAccount(ctx context.Context, account *OAuthAccount) error {
	return a.q.UpdateOAuthAccount(ctx, pgstore.UpdateOAuthAccountParams{
		ID:                   account.ID,
		AccessToken:          toNullString(account.AccessToken),
		RefreshToken:         toNullString(account.RefreshToken),
		AccessTokenExpiresAt: toNullTime(account.AccessTokenExpiresAt),
		UpdatedAt:            time.Now(),
	})
}

func (a *pgAdapter) DeleteOAuthAccount(ctx context.Context, id string) error {
	return a.q.DeleteOAuthAccount(ctx, id)
}

// =============================================================================
// WebAuthn Credential operations
// =============================================================================

func (a *pgAdapter) CreateWebAuthnCredential(ctx context.Context, cred *WebAuthnCredential) error {
	// Parse transports from comma-separated string to []string
	var transports []string
	if cred.Transports != nil && *cred.Transports != "" {
		transports = strings.Split(*cred.Transports, ",")
	}
	return a.q.CreateWebAuthnCredential(ctx, pgstore.CreateWebAuthnCredentialParams{
		ID:           cred.ID,
		UserID:       cred.UserID,
		CredentialID: cred.CredentialID,
		PublicKey:    cred.PublicKey,
		SignCount:    int32(cred.SignCount),
		Transports:   transports,
		CreatedAt:    cred.CreatedAt,
		LastUsedAt:   toNullTime(cred.LastUsedAt),
	})
}

func (a *pgAdapter) GetWebAuthnCredentialByID(ctx context.Context, credentialID []byte) (*WebAuthnCredential, error) {
	c, err := a.q.GetWebAuthnCredentialByID(ctx, credentialID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return pgWebAuthnCredentialToModel(&c), nil
}

func (a *pgAdapter) ListWebAuthnCredentialsByUserID(ctx context.Context, userID string) ([]*WebAuthnCredential, error) {
	creds, err := a.q.ListWebAuthnCredentialsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	result := make([]*WebAuthnCredential, len(creds))
	for i := range creds {
		result[i] = pgWebAuthnCredentialToModel(&creds[i])
	}
	return result, nil
}

func (a *pgAdapter) UpdateWebAuthnCredentialSignCount(ctx context.Context, id string, signCount int64) error {
	now := time.Now()
	return a.q.UpdateWebAuthnCredentialSignCount(ctx, pgstore.UpdateWebAuthnCredentialSignCountParams{
		ID:         id,
		SignCount:  int32(signCount),
		LastUsedAt: sql.NullTime{Time: now, Valid: true},
	})
}

func (a *pgAdapter) DeleteWebAuthnCredential(ctx context.Context, id string) error {
	return a.q.DeleteWebAuthnCredential(ctx, id)
}

// =============================================================================
// WebAuthn Session operations
// =============================================================================

func (a *pgAdapter) CreateWebAuthnSession(ctx context.Context, session *WebAuthnSession) error {
	return a.q.CreateWebAuthnSession(ctx, pgstore.CreateWebAuthnSessionParams{
		ID:        session.ID,
		UserID:    toNullString(session.UserID),
		Type:      session.Type,
		Data:      session.Data,
		ExpiresAt: session.ExpiresAt,
		CreatedAt: session.CreatedAt,
	})
}

func (a *pgAdapter) GetWebAuthnSession(ctx context.Context, id string) (*WebAuthnSession, error) {
	s, err := a.q.GetWebAuthnSession(ctx, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return pgWebAuthnSessionToModel(&s), nil
}

func (a *pgAdapter) DeleteWebAuthnSession(ctx context.Context, id string) error {
	return a.q.DeleteWebAuthnSession(ctx, id)
}

func (a *pgAdapter) DeleteExpiredWebAuthnSessions(ctx context.Context) error {
	return a.q.DeleteExpiredWebAuthnSessions(ctx, time.Now())
}

// =============================================================================
// API Key operations
// =============================================================================

func (a *pgAdapter) CreateAPIKey(ctx context.Context, key *APIKey) error {
	return a.q.CreateAPIKey(ctx, pgstore.CreateAPIKeyParams{
		ID:                  key.ID,
		Name:                toNullString(key.Name),
		Start:               key.Start,
		Prefix:              toNullString(key.Prefix),
		Key:                 key.Key,
		KeyPrefix:           key.KeyPrefix,
		UserID:              key.UserID,
		RateLimitEnabled:    key.RateLimitEnabled,
		RateLimitTimeWindow: toNullInt64(key.RateLimitTimeWindow),
		RateLimitMax:        toNullInt32(key.RateLimitMax),
		RequestCount:        key.RequestCount,
		Remaining:           toNullInt32(key.Remaining),
		RefillInterval:      toNullInt64(key.RefillInterval),
		RefillAmount:        toNullInt32(key.RefillAmount),
		LastRefillAt:        toNullTime(key.LastRefillAt),
		Enabled:             key.Enabled,
		LastRequest:         toNullTime(key.LastRequest),
		ExpiresAt:           toNullTime(key.ExpiresAt),
		Permissions:         toNullString(key.Permissions),
		Metadata:            toNullString(key.Metadata),
		CreatedAt:           key.CreatedAt,
		UpdatedAt:           key.UpdatedAt,
	})
}

func (a *pgAdapter) GetAPIKeyByID(ctx context.Context, id string) (*APIKey, error) {
	k, err := a.q.GetAPIKeyByID(ctx, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return pgAPIKeyToModel(&k), nil
}

func (a *pgAdapter) GetAPIKeyByKeyPrefix(ctx context.Context, keyPrefix string) ([]*APIKey, error) {
	keys, err := a.q.GetAPIKeyByKeyPrefix(ctx, keyPrefix)
	if err != nil {
		return nil, err
	}
	result := make([]*APIKey, len(keys))
	for i := range keys {
		result[i] = pgAPIKeyToModel(&keys[i])
	}
	return result, nil
}

func (a *pgAdapter) ListAPIKeysByUserID(ctx context.Context, userID string) ([]*APIKey, error) {
	keys, err := a.q.ListAPIKeysByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	result := make([]*APIKey, len(keys))
	for i := range keys {
		result[i] = pgAPIKeyToModel(&keys[i])
	}
	return result, nil
}

func (a *pgAdapter) UpdateAPIKey(ctx context.Context, key *APIKey) error {
	return a.q.UpdateAPIKey(ctx, pgstore.UpdateAPIKeyParams{
		ID:                  key.ID,
		Name:                toNullString(key.Name),
		RateLimitEnabled:    key.RateLimitEnabled,
		RateLimitTimeWindow: toNullInt64(key.RateLimitTimeWindow),
		RateLimitMax:        toNullInt32(key.RateLimitMax),
		Remaining:           toNullInt32(key.Remaining),
		RefillInterval:      toNullInt64(key.RefillInterval),
		RefillAmount:        toNullInt32(key.RefillAmount),
		Enabled:             key.Enabled,
		ExpiresAt:           toNullTime(key.ExpiresAt),
		Permissions:         toNullString(key.Permissions),
		Metadata:            toNullString(key.Metadata),
		UpdatedAt:           time.Now(),
	})
}

func (a *pgAdapter) UpdateAPIKeyUsage(ctx context.Context, key *APIKey) error {
	return a.q.UpdateAPIKeyUsage(ctx, pgstore.UpdateAPIKeyUsageParams{
		ID:           key.ID,
		RequestCount: key.RequestCount,
		Remaining:    toNullInt32(key.Remaining),
		LastRequest:  toNullTime(key.LastRequest),
		LastRefillAt: toNullTime(key.LastRefillAt),
		UpdatedAt:    time.Now(),
	})
}

func (a *pgAdapter) DeleteAPIKey(ctx context.Context, id string) error {
	return a.q.DeleteAPIKey(ctx, id)
}

func (a *pgAdapter) DeleteAPIKeysByUserID(ctx context.Context, userID string) error {
	return a.q.DeleteAPIKeysByUserID(ctx, userID)
}

// =============================================================================
// JWT Key operations
// =============================================================================

func (a *pgAdapter) CreateJWTKey(ctx context.Context, key *JWTKey) error {
	return a.q.CreateJWTKey(ctx, pgstore.CreateJWTKeyParams{
		ID:            key.ID,
		Algorithm:     key.Algorithm,
		Use:           key.Use,
		Kty:           key.KeyType,
		Status:        key.Status,
		PrivateKeyEnc: key.PrivateKeyEnc,
		PublicKeyJwk:  key.PublicKeyJWK,
		ActivatedAt:   key.ActivatedAt,
		CreatedAt:     key.CreatedAt,
		UpdatedAt:     key.UpdatedAt,
	})
}

func (a *pgAdapter) GetJWTKeyByID(ctx context.Context, id string) (*JWTKey, error) {
	k, err := a.q.GetJWTKeyByID(ctx, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return pgJWTKeyToModel(&k), nil
}

func (a *pgAdapter) GetActiveJWTKey(ctx context.Context, algorithm string) (*JWTKey, error) {
	k, err := a.q.GetActiveJWTKey(ctx, algorithm)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return pgJWTKeyToModel(&k), nil
}

func (a *pgAdapter) GetJWTKeysForVerification(ctx context.Context, algorithm string) ([]*JWTKey, error) {
	keys, err := a.q.GetJWTKeysForVerification(ctx, pgstore.GetJWTKeysForVerificationParams{
		Algorithm: algorithm,
		ExpiresAt: sql.NullTime{Time: time.Now(), Valid: true},
	})
	if err != nil {
		return nil, err
	}
	result := make([]*JWTKey, len(keys))
	for i := range keys {
		result[i] = pgJWTKeyToModel(&keys[i])
	}
	return result, nil
}

func (a *pgAdapter) GetJWTKeyForVerification(ctx context.Context, id string) (*JWTKey, error) {
	k, err := a.q.GetJWTKeyForVerification(ctx, pgstore.GetJWTKeyForVerificationParams{
		ID:        id,
		ExpiresAt: sql.NullTime{Time: time.Now(), Valid: true},
	})
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return pgJWTKeyToModel(&k), nil
}

func (a *pgAdapter) RotateActiveJWTKeys(ctx context.Context, algorithm string, expiresAt time.Time) error {
	now := time.Now()
	return a.q.RotateActiveJWTKeys(ctx, pgstore.RotateActiveJWTKeysParams{
		RotatedAt: sql.NullTime{Time: now, Valid: true},
		ExpiresAt: sql.NullTime{Time: expiresAt, Valid: true},
		UpdatedAt: now,
		Algorithm: algorithm,
	})
}

func (a *pgAdapter) RetireExpiredJWTKeys(ctx context.Context) (int64, error) {
	return a.q.RetireExpiredJWTKeys(ctx, pgstore.RetireExpiredJWTKeysParams{
		UpdatedAt: time.Now(),
		ExpiresAt: sql.NullTime{Time: time.Now(), Valid: true},
	})
}

func (a *pgAdapter) DeleteJWTKey(ctx context.Context, id string) error {
	return a.q.DeleteJWTKey(ctx, id)
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

// =============================================================================
// Device Authorization operations
// =============================================================================

func (a *pgAdapter) CreateDeviceCode(ctx context.Context, code *DeviceCode) error {
	return a.q.CreateDeviceCode(ctx, pgstore.CreateDeviceCodeParams{
		ID:              code.ID,
		DeviceCode:      code.DeviceCode,
		DeviceCodeHash:  code.DeviceCodeHash,
		UserCode:        code.UserCode,
		ClientID:        toNullString(code.ClientID),
		Scope:           toNullString(code.Scope),
		UserID:          toNullString(code.UserID),
		Status:          code.Status,
		PollingInterval: int32(code.PollingInterval),
		LastPolledAt:    toNullTime(code.LastPolledAt),
		ExpiresAt:       code.ExpiresAt,
		CreatedAt:       code.CreatedAt,
		UpdatedAt:       code.UpdatedAt,
	})
}

func (a *pgAdapter) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error) {
	row, err := a.q.GetDeviceCodeByUserCode(ctx, userCode)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return pgDeviceCodeToModel(&row), nil
}

func (a *pgAdapter) GetDeviceCodeByHash(ctx context.Context, hashPrefix, fullHash string) (*DeviceCode, error) {
	row, err := a.q.GetDeviceCodeByHash(ctx, pgstore.GetDeviceCodeByHashParams{
		DeviceCodeHash: hashPrefix,
		DeviceCode:     fullHash,
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return pgDeviceCodeToModel(&row), nil
}

func (a *pgAdapter) UpdateDeviceCodeStatus(ctx context.Context, id, status string, userID *string) error {
	return a.q.UpdateDeviceCodeStatus(ctx, pgstore.UpdateDeviceCodeStatusParams{
		ID:        id,
		Status:    status,
		UserID:    toNullString(userID),
		UpdatedAt: time.Now(),
	})
}

func (a *pgAdapter) UpdateDeviceCodeLastPolled(ctx context.Context, id string, lastPolledAt time.Time) error {
	return a.q.UpdateDeviceCodeLastPolled(ctx, pgstore.UpdateDeviceCodeLastPolledParams{
		ID:           id,
		LastPolledAt: sql.NullTime{Time: lastPolledAt, Valid: true},
		UpdatedAt:    time.Now(),
	})
}

func (a *pgAdapter) DeleteExpiredDeviceCodes(ctx context.Context) (int64, error) {
	return a.q.DeleteExpiredDeviceCodes(ctx)
}

func (a *pgAdapter) DeleteDeviceCode(ctx context.Context, id string) error {
	return a.q.DeleteDeviceCode(ctx, id)
}

// Ensure pgAdapter implements Querier
var _ Querier = (*pgAdapter)(nil)
