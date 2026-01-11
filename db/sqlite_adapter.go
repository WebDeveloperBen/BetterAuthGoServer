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
// OTP operations
// =============================================================================

func (a *sqliteAdapter) CreateOTPToken(ctx context.Context, token *OTPToken) error {
	return a.q.CreateOTPToken(ctx, sqlitestore.CreateOTPTokenParams{
		ID:         token.ID,
		UserID:     token.UserID,
		TokenHash:  token.TokenHash,
		Type:       token.Type,
		Identifier: toNullString(token.Identifier),
		ExpiresAt:  token.ExpiresAt.Format(time.RFC3339),
		CreatedAt:  token.CreatedAt.Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) GetOTPTokenByHash(ctx context.Context, tokenHash string) (*OTPToken, error) {
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
		ExpiresAt:  parseTime(t.ExpiresAt),
		CreatedAt:  parseTime(t.CreatedAt),
	}, nil
}

func (a *sqliteAdapter) DeleteOTPToken(ctx context.Context, id string) error {
	return a.q.DeleteOTPToken(ctx, id)
}

func (a *sqliteAdapter) DeleteOTPTokensByUserAndType(ctx context.Context, userID, tokenType string) error {
	return a.q.DeleteOTPTokensByUserAndType(ctx, sqlitestore.DeleteOTPTokensByUserAndTypeParams{
		UserID: userID,
		Type:   tokenType,
	})
}

func (a *sqliteAdapter) DeleteExpiredOTPTokens(ctx context.Context) error {
	return a.q.DeleteExpiredOTPTokens(ctx, time.Now().Format(time.RFC3339))
}

// =============================================================================
// JWT operations
// =============================================================================

func (a *sqliteAdapter) RevokeJWTToken(ctx context.Context, jti string, expiresAt time.Time) error {
	return a.q.RevokeJWTToken(ctx, sqlitestore.RevokeJWTTokenParams{
		ID:        jti,
		ExpiresAt: expiresAt.Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) IsJWTTokenRevoked(ctx context.Context, jti string) (bool, error) {
	count, err := a.q.IsJWTTokenRevoked(ctx, jti)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (a *sqliteAdapter) DeleteExpiredRevokedTokens(ctx context.Context) error {
	return a.q.DeleteExpiredRevokedTokens(ctx, time.Now().Format(time.RFC3339))
}

// =============================================================================
// OAuth State operations
// =============================================================================

func (a *sqliteAdapter) CreateOAuthState(ctx context.Context, state *OAuthState) error {
	return a.q.CreateOAuthState(ctx, sqlitestore.CreateOAuthStateParams{
		State:      state.State,
		Provider:   state.Provider,
		Verifier:   toNullString(state.Verifier),
		RedirectTo: toNullString(state.RedirectTo),
		ExpiresAt:  state.ExpiresAt.Format(time.RFC3339),
		CreatedAt:  state.CreatedAt.Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) GetOAuthState(ctx context.Context, state string) (*OAuthState, error) {
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
		ExpiresAt:  parseTime(s.ExpiresAt),
		CreatedAt:  parseTime(s.CreatedAt),
	}, nil
}

func (a *sqliteAdapter) DeleteOAuthState(ctx context.Context, state string) error {
	return a.q.DeleteOAuthState(ctx, state)
}

func (a *sqliteAdapter) DeleteExpiredOAuthStates(ctx context.Context) error {
	return a.q.DeleteExpiredOAuthStates(ctx, time.Now().Format(time.RFC3339))
}

// =============================================================================
// OAuth Account operations
// =============================================================================

func (a *sqliteAdapter) CreateOAuthAccount(ctx context.Context, account *OAuthAccount) error {
	return a.q.CreateOAuthAccount(ctx, sqlitestore.CreateOAuthAccountParams{
		ID:                   account.ID,
		UserID:               account.UserID,
		Provider:             account.Provider,
		ProviderAccountID:    account.ProviderAccountID,
		AccessToken:          toNullString(account.AccessToken),
		RefreshToken:         toNullString(account.RefreshToken),
		AccessTokenExpiresAt: toNullString(timeToString(account.AccessTokenExpiresAt)),
		CreatedAt:            account.CreatedAt.Format(time.RFC3339),
		UpdatedAt:            account.UpdatedAt.Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) GetOAuthAccountByProvider(ctx context.Context, provider, providerAccountID string) (*OAuthAccount, error) {
	acc, err := a.q.GetOAuthAccountByProvider(ctx, sqlitestore.GetOAuthAccountByProviderParams{
		Provider:          provider,
		ProviderAccountID: providerAccountID,
	})
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return sqliteOAuthAccountToModel(&acc), nil
}

func (a *sqliteAdapter) GetOAuthAccountsByUserID(ctx context.Context, userID string) ([]*OAuthAccount, error) {
	accounts, err := a.q.GetOAuthAccountsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	result := make([]*OAuthAccount, len(accounts))
	for i := range accounts {
		result[i] = sqliteOAuthAccountToModel(&accounts[i])
	}
	return result, nil
}

func (a *sqliteAdapter) UpdateOAuthAccount(ctx context.Context, account *OAuthAccount) error {
	return a.q.UpdateOAuthAccount(ctx, sqlitestore.UpdateOAuthAccountParams{
		ID:                   account.ID,
		AccessToken:          toNullString(account.AccessToken),
		RefreshToken:         toNullString(account.RefreshToken),
		AccessTokenExpiresAt: toNullString(timeToString(account.AccessTokenExpiresAt)),
		UpdatedAt:            time.Now().Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) DeleteOAuthAccount(ctx context.Context, id string) error {
	return a.q.DeleteOAuthAccount(ctx, id)
}

// =============================================================================
// WebAuthn Credential operations
// =============================================================================

func (a *sqliteAdapter) CreateWebAuthnCredential(ctx context.Context, cred *WebAuthnCredential) error {
	return a.q.CreateWebAuthnCredential(ctx, sqlitestore.CreateWebAuthnCredentialParams{
		ID:           cred.ID,
		UserID:       cred.UserID,
		CredentialID: cred.CredentialID,
		PublicKey:    cred.PublicKey,
		SignCount:    cred.SignCount,
		Transports:   toNullString(cred.Transports),
		CreatedAt:    cred.CreatedAt.Format(time.RFC3339),
		LastUsedAt:   toNullString(timeToString(cred.LastUsedAt)),
	})
}

func (a *sqliteAdapter) GetWebAuthnCredentialByID(ctx context.Context, credentialID []byte) (*WebAuthnCredential, error) {
	c, err := a.q.GetWebAuthnCredentialByID(ctx, credentialID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return sqliteWebAuthnCredentialToModel(&c), nil
}

func (a *sqliteAdapter) ListWebAuthnCredentialsByUserID(ctx context.Context, userID string) ([]*WebAuthnCredential, error) {
	creds, err := a.q.ListWebAuthnCredentialsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	result := make([]*WebAuthnCredential, len(creds))
	for i := range creds {
		result[i] = sqliteWebAuthnCredentialToModel(&creds[i])
	}
	return result, nil
}

func (a *sqliteAdapter) UpdateWebAuthnCredentialSignCount(ctx context.Context, id string, signCount int64) error {
	now := time.Now().Format(time.RFC3339)
	return a.q.UpdateWebAuthnCredentialSignCount(ctx, sqlitestore.UpdateWebAuthnCredentialSignCountParams{
		ID:         id,
		SignCount:  signCount,
		LastUsedAt: sql.NullString{String: now, Valid: true},
	})
}

func (a *sqliteAdapter) DeleteWebAuthnCredential(ctx context.Context, id string) error {
	return a.q.DeleteWebAuthnCredential(ctx, id)
}

// =============================================================================
// WebAuthn Session operations
// =============================================================================

func (a *sqliteAdapter) CreateWebAuthnSession(ctx context.Context, session *WebAuthnSession) error {
	return a.q.CreateWebAuthnSession(ctx, sqlitestore.CreateWebAuthnSessionParams{
		ID:        session.ID,
		UserID:    toNullString(session.UserID),
		Type:      session.Type,
		Data:      session.Data,
		ExpiresAt: session.ExpiresAt.Format(time.RFC3339),
		CreatedAt: session.CreatedAt.Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) GetWebAuthnSession(ctx context.Context, id string) (*WebAuthnSession, error) {
	s, err := a.q.GetWebAuthnSession(ctx, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return sqliteWebAuthnSessionToModel(&s), nil
}

func (a *sqliteAdapter) DeleteWebAuthnSession(ctx context.Context, id string) error {
	return a.q.DeleteWebAuthnSession(ctx, id)
}

func (a *sqliteAdapter) DeleteExpiredWebAuthnSessions(ctx context.Context) error {
	return a.q.DeleteExpiredWebAuthnSessions(ctx, time.Now().Format(time.RFC3339))
}

// =============================================================================
// API Key operations
// =============================================================================

func (a *sqliteAdapter) CreateAPIKey(ctx context.Context, key *APIKey) error {
	return a.q.CreateAPIKey(ctx, sqlitestore.CreateAPIKeyParams{
		ID:                  key.ID,
		Name:                toNullString(key.Name),
		Start:               key.Start,
		Prefix:              toNullString(key.Prefix),
		Key:                 key.Key,
		KeyPrefix:           key.KeyPrefix,
		UserID:              key.UserID,
		RateLimitEnabled:    boolToInt(key.RateLimitEnabled),
		RateLimitTimeWindow: toNullInt64(key.RateLimitTimeWindow),
		RateLimitMax:        int32ToNullInt64(key.RateLimitMax),
		RequestCount:        int64(key.RequestCount),
		Remaining:           int32ToNullInt64(key.Remaining),
		RefillInterval:      toNullInt64(key.RefillInterval),
		RefillAmount:        int32ToNullInt64(key.RefillAmount),
		LastRefillAt:        toNullString(timeToString(key.LastRefillAt)),
		Enabled:             boolToInt(key.Enabled),
		LastRequest:         toNullString(timeToString(key.LastRequest)),
		ExpiresAt:           toNullString(timeToString(key.ExpiresAt)),
		Permissions:         toNullString(key.Permissions),
		Metadata:            toNullString(key.Metadata),
		CreatedAt:           key.CreatedAt.Format(time.RFC3339),
		UpdatedAt:           key.UpdatedAt.Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) GetAPIKeyByID(ctx context.Context, id string) (*APIKey, error) {
	k, err := a.q.GetAPIKeyByID(ctx, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return sqliteAPIKeyToModel(&k), nil
}

func (a *sqliteAdapter) GetAPIKeyByKeyPrefix(ctx context.Context, keyPrefix string) ([]*APIKey, error) {
	keys, err := a.q.GetAPIKeyByKeyPrefix(ctx, keyPrefix)
	if err != nil {
		return nil, err
	}
	result := make([]*APIKey, len(keys))
	for i := range keys {
		result[i] = sqliteAPIKeyToModel(&keys[i])
	}
	return result, nil
}

func (a *sqliteAdapter) ListAPIKeysByUserID(ctx context.Context, userID string) ([]*APIKey, error) {
	keys, err := a.q.ListAPIKeysByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	result := make([]*APIKey, len(keys))
	for i := range keys {
		result[i] = sqliteAPIKeyToModel(&keys[i])
	}
	return result, nil
}

func (a *sqliteAdapter) UpdateAPIKey(ctx context.Context, key *APIKey) error {
	return a.q.UpdateAPIKey(ctx, sqlitestore.UpdateAPIKeyParams{
		ID:                  key.ID,
		Name:                toNullString(key.Name),
		RateLimitEnabled:    boolToInt(key.RateLimitEnabled),
		RateLimitTimeWindow: toNullInt64(key.RateLimitTimeWindow),
		RateLimitMax:        int32ToNullInt64(key.RateLimitMax),
		Remaining:           int32ToNullInt64(key.Remaining),
		RefillInterval:      toNullInt64(key.RefillInterval),
		RefillAmount:        int32ToNullInt64(key.RefillAmount),
		Enabled:             boolToInt(key.Enabled),
		ExpiresAt:           toNullString(timeToString(key.ExpiresAt)),
		Permissions:         toNullString(key.Permissions),
		Metadata:            toNullString(key.Metadata),
		UpdatedAt:           time.Now().Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) UpdateAPIKeyUsage(ctx context.Context, key *APIKey) error {
	return a.q.UpdateAPIKeyUsage(ctx, sqlitestore.UpdateAPIKeyUsageParams{
		ID:           key.ID,
		RequestCount: int64(key.RequestCount),
		Remaining:    int32ToNullInt64(key.Remaining),
		LastRequest:  toNullString(timeToString(key.LastRequest)),
		LastRefillAt: toNullString(timeToString(key.LastRefillAt)),
		UpdatedAt:    time.Now().Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) DeleteAPIKey(ctx context.Context, id string) error {
	return a.q.DeleteAPIKey(ctx, id)
}

func (a *sqliteAdapter) DeleteAPIKeysByUserID(ctx context.Context, userID string) error {
	return a.q.DeleteAPIKeysByUserID(ctx, userID)
}

// =============================================================================
// JWT Key operations
// =============================================================================

func (a *sqliteAdapter) CreateJWTKey(ctx context.Context, key *JWTKey) error {
	return a.q.CreateJWTKey(ctx, sqlitestore.CreateJWTKeyParams{
		ID:            key.ID,
		Algorithm:     key.Algorithm,
		Use:           key.Use,
		Kty:           key.KeyType,
		Status:        key.Status,
		PrivateKeyEnc: key.PrivateKeyEnc,
		PublicKeyJwk:  key.PublicKeyJWK,
		ActivatedAt:   key.ActivatedAt.Format(time.RFC3339),
		CreatedAt:     key.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     key.UpdatedAt.Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) GetJWTKeyByID(ctx context.Context, id string) (*JWTKey, error) {
	k, err := a.q.GetJWTKeyByID(ctx, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return sqliteJWTKeyToModel(&k), nil
}

func (a *sqliteAdapter) GetActiveJWTKey(ctx context.Context, algorithm string) (*JWTKey, error) {
	k, err := a.q.GetActiveJWTKey(ctx, algorithm)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return sqliteJWTKeyToModel(&k), nil
}

func (a *sqliteAdapter) GetJWTKeysForVerification(ctx context.Context, algorithm string) ([]*JWTKey, error) {
	keys, err := a.q.GetJWTKeysForVerification(ctx, sqlitestore.GetJWTKeysForVerificationParams{
		Algorithm: algorithm,
		ExpiresAt: sql.NullString{String: time.Now().Format(time.RFC3339), Valid: true},
	})
	if err != nil {
		return nil, err
	}
	result := make([]*JWTKey, len(keys))
	for i := range keys {
		result[i] = sqliteJWTKeyToModel(&keys[i])
	}
	return result, nil
}

func (a *sqliteAdapter) GetJWTKeyForVerification(ctx context.Context, id string) (*JWTKey, error) {
	k, err := a.q.GetJWTKeyForVerification(ctx, sqlitestore.GetJWTKeyForVerificationParams{
		ID:        id,
		ExpiresAt: sql.NullString{String: time.Now().Format(time.RFC3339), Valid: true},
	})
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return sqliteJWTKeyToModel(&k), nil
}

func (a *sqliteAdapter) RotateActiveJWTKeys(ctx context.Context, algorithm string, expiresAt time.Time) error {
	now := time.Now()
	return a.q.RotateActiveJWTKeys(ctx, sqlitestore.RotateActiveJWTKeysParams{
		RotatedAt: sql.NullString{String: now.Format(time.RFC3339), Valid: true},
		ExpiresAt: sql.NullString{String: expiresAt.Format(time.RFC3339), Valid: true},
		UpdatedAt: now.Format(time.RFC3339),
		Algorithm: algorithm,
	})
}

func (a *sqliteAdapter) RetireExpiredJWTKeys(ctx context.Context) (int64, error) {
	return a.q.RetireExpiredJWTKeys(ctx, sqlitestore.RetireExpiredJWTKeysParams{
		UpdatedAt: time.Now().Format(time.RFC3339),
		ExpiresAt: sql.NullString{String: time.Now().Format(time.RFC3339), Valid: true},
	})
}

func (a *sqliteAdapter) DeleteJWTKey(ctx context.Context, id string) error {
	return a.q.DeleteJWTKey(ctx, id)
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

// =============================================================================
// Device Authorization operations
// =============================================================================

func (a *sqliteAdapter) CreateDeviceCode(ctx context.Context, code *DeviceCode) error {
	var lastPolledAt sql.NullString
	if code.LastPolledAt != nil {
		lastPolledAt = sql.NullString{String: code.LastPolledAt.Format(time.RFC3339), Valid: true}
	}
	return a.q.CreateDeviceCode(ctx, sqlitestore.CreateDeviceCodeParams{
		ID:              code.ID,
		DeviceCode:      code.DeviceCode,
		DeviceCodeHash:  code.DeviceCodeHash,
		UserCode:        code.UserCode,
		ClientID:        toNullString(code.ClientID),
		Scope:           toNullString(code.Scope),
		UserID:          toNullString(code.UserID),
		Status:          code.Status,
		PollingInterval: int64(code.PollingInterval),
		LastPolledAt:    lastPolledAt,
		ExpiresAt:       code.ExpiresAt.Format(time.RFC3339),
		CreatedAt:       code.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       code.UpdatedAt.Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error) {
	row, err := a.q.GetDeviceCodeByUserCode(ctx, userCode)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteDeviceCodeToModel(&row), nil
}

func (a *sqliteAdapter) GetDeviceCodeByHash(ctx context.Context, hashPrefix, fullHash string) (*DeviceCode, error) {
	row, err := a.q.GetDeviceCodeByHash(ctx, sqlitestore.GetDeviceCodeByHashParams{
		DeviceCodeHash: hashPrefix,
		DeviceCode:     fullHash,
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteDeviceCodeToModel(&row), nil
}

func (a *sqliteAdapter) UpdateDeviceCodeStatus(ctx context.Context, id, status string, userID *string) error {
	return a.q.UpdateDeviceCodeStatus(ctx, sqlitestore.UpdateDeviceCodeStatusParams{
		Status:    status,
		UserID:    toNullString(userID),
		UpdatedAt: time.Now().Format(time.RFC3339),
		ID:        id,
	})
}

func (a *sqliteAdapter) UpdateDeviceCodeLastPolled(ctx context.Context, id string, lastPolledAt time.Time) error {
	return a.q.UpdateDeviceCodeLastPolled(ctx, sqlitestore.UpdateDeviceCodeLastPolledParams{
		LastPolledAt: sql.NullString{String: lastPolledAt.Format(time.RFC3339), Valid: true},
		UpdatedAt:    time.Now().Format(time.RFC3339),
		ID:           id,
	})
}

func (a *sqliteAdapter) DeleteExpiredDeviceCodes(ctx context.Context) (int64, error) {
	return a.q.DeleteExpiredDeviceCodes(ctx)
}

func (a *sqliteAdapter) DeleteDeviceCode(ctx context.Context, id string) error {
	return a.q.DeleteDeviceCode(ctx, id)
}

// Ensure sqliteAdapter implements Querier
var _ Querier = (*sqliteAdapter)(nil)
