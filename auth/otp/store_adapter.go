package otp

import (
	"context"

	otpdb "github.com/webdeveloperben/BetterAuthGoServer/auth/otp/db"
)

// StoreAdapter adapts the OTP plugin's db.Store to the TokenStore interface.
type StoreAdapter struct {
	store *otpdb.Store
}

// NewStoreAdapter creates a new OTP store adapter from the plugin's own store.
func NewStoreAdapter(store *otpdb.Store) *StoreAdapter {
	return &StoreAdapter{store: store}
}

// Create stores a new OTP token.
func (a *StoreAdapter) Create(ctx context.Context, token *OTPToken) error {
	dbToken := &otpdb.Token{
		ID:         token.ID,
		UserID:     token.UserID,
		TokenHash:  token.TokenHash,
		Type:       string(token.Type),
		Identifier: token.Identifier,
		ExpiresAt:  token.ExpiresAt,
		CreatedAt:  token.CreatedAt,
	}
	return a.store.CreateToken(ctx, dbToken)
}

// GetByTokenHash retrieves a token by its hash.
func (a *StoreAdapter) GetByTokenHash(ctx context.Context, tokenHash string) (*OTPToken, error) {
	dbToken, err := a.store.GetTokenByHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}
	if dbToken == nil {
		return nil, nil
	}
	return a.toOTPToken(dbToken), nil
}

// Delete removes a token by ID.
func (a *StoreAdapter) Delete(ctx context.Context, id string) error {
	return a.store.DeleteToken(ctx, id)
}

// DeleteByUserAndType removes all tokens of a specific type for a user.
func (a *StoreAdapter) DeleteByUserAndType(ctx context.Context, userID string, tokenType TokenType) error {
	return a.store.DeleteTokensByUserAndType(ctx, userID, string(tokenType))
}

// DeleteExpired removes all expired tokens.
func (a *StoreAdapter) DeleteExpired(ctx context.Context) error {
	return a.store.DeleteExpiredTokens(ctx)
}

// toOTPToken converts an otpdb.Token to an OTPToken.
func (a *StoreAdapter) toOTPToken(t *otpdb.Token) *OTPToken {
	return &OTPToken{
		ID:         t.ID,
		UserID:     t.UserID,
		TokenHash:  t.TokenHash,
		Type:       TokenType(t.Type),
		Identifier: t.Identifier,
		ExpiresAt:  t.ExpiresAt,
		CreatedAt:  t.CreatedAt,
	}
}

// Ensure StoreAdapter implements TokenStore
var _ TokenStore = (*StoreAdapter)(nil)
