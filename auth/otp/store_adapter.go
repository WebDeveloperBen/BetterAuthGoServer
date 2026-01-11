package otp

import (
	"context"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/db"
)

// StoreAdapter adapts db.OTPStore to the OTP package's Store interface.
type StoreAdapter struct {
	store db.OTPStore
}

// NewStoreAdapter creates a new OTP store adapter from a db.OTPStore.
func NewStoreAdapter(store db.OTPStore) *StoreAdapter {
	return &StoreAdapter{store: store}
}

// Create stores a new OTP token.
func (a *StoreAdapter) Create(ctx context.Context, token *OTPToken) error {
	dbToken := &db.OTPToken{
		ID:         token.ID,
		UserID:     token.UserID,
		TokenHash:  token.TokenHash,
		Type:       string(token.Type),
		Identifier: token.Identifier,
		ExpiresAt:  token.ExpiresAt,
		CreatedAt:  token.CreatedAt,
	}
	return a.store.CreateOTPToken(ctx, dbToken)
}

// GetByTokenHash retrieves a token by its hash.
func (a *StoreAdapter) GetByTokenHash(ctx context.Context, tokenHash string) (*OTPToken, error) {
	dbToken, err := a.store.GetOTPTokenByHash(ctx, tokenHash)
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
	return a.store.DeleteOTPToken(ctx, id)
}

// DeleteByUserAndType removes all tokens of a specific type for a user.
func (a *StoreAdapter) DeleteByUserAndType(ctx context.Context, userID string, tokenType TokenType) error {
	return a.store.DeleteOTPTokensByUserAndType(ctx, userID, string(tokenType))
}

// DeleteExpired removes all expired tokens.
func (a *StoreAdapter) DeleteExpired(ctx context.Context) error {
	return a.store.DeleteExpiredOTPTokens(ctx)
}

// toOTPToken converts a db.OTPToken to an OTPToken.
func (a *StoreAdapter) toOTPToken(t *db.OTPToken) *OTPToken {
	var expiresAt time.Time
	expiresAt = t.ExpiresAt

	return &OTPToken{
		ID:         t.ID,
		UserID:     t.UserID,
		TokenHash:  t.TokenHash,
		Type:       TokenType(t.Type),
		Identifier: t.Identifier,
		ExpiresAt:  expiresAt,
		CreatedAt:  t.CreatedAt,
	}
}

// Ensure StoreAdapter has the same methods as Store
var _ interface {
	Create(ctx context.Context, token *OTPToken) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*OTPToken, error)
	Delete(ctx context.Context, id string) error
	DeleteByUserAndType(ctx context.Context, userID string, tokenType TokenType) error
	DeleteExpired(ctx context.Context) error
} = (*StoreAdapter)(nil)
