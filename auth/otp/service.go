package otp

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/token"
)

// TokenType represents the type of OTP token.
type TokenType string

const (
	TokenTypePasswordReset     TokenType = "password_reset"
	TokenTypeEmailVerification TokenType = "email_verification"
	TokenTypeEmailChange       TokenType = "email_change"
)

// OTPToken represents an OTP token record.
// These are one-time use tokens for verification flows like password reset and email verification.
type OTPToken struct {
	ID         string
	UserID     string
	TokenHash  string
	Type       TokenType
	Identifier *string // For email_change: new email address
	ExpiresAt  time.Time
	CreatedAt  time.Time
}

// IsExpired returns true if the token has expired.
func (t *OTPToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// TokenStore defines the interface for OTP token persistence.
type TokenStore interface {
	Create(ctx context.Context, token *OTPToken) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*OTPToken, error)
	Delete(ctx context.Context, id string) error
	DeleteByUserAndType(ctx context.Context, userID string, tokenType TokenType) error
	DeleteExpired(ctx context.Context) error
}

// Service handles OTP token operations.
type Service struct {
	store  TokenStore
	hasher *token.Hasher
	config Config
}

// NewService creates a new OTP service.
func NewService(store TokenStore, hasher *token.Hasher, config Config) *Service {
	return &Service{
		store:  store,
		hasher: hasher,
		config: config,
	}
}

// CreateToken generates a new verification token, stores it, and returns the raw token.
// The raw token should be sent to the user (e.g., via email) while only the hash is stored.
// Any existing tokens of the same type for this user are deleted first.
func (s *Service) CreateToken(ctx context.Context, userID string, tokenType TokenType) (string, error) {
	expiry := s.expiryForType(tokenType)
	return s.createTokenWithExpiry(ctx, userID, tokenType, nil, expiry)
}

// CreateTokenWithIdentifier generates a verification token with an associated identifier.
// This is used for operations like email change where we need to store the new email.
func (s *Service) CreateTokenWithIdentifier(ctx context.Context, userID string, tokenType TokenType, identifier string) (string, error) {
	expiry := s.expiryForType(tokenType)
	return s.createTokenWithExpiry(ctx, userID, tokenType, &identifier, expiry)
}

// ValidateToken validates a raw token and returns the token record if valid.
// The token is NOT consumed (deleted) - use ConsumeToken for that.
func (s *Service) ValidateToken(ctx context.Context, rawToken string, expectedType TokenType) (*OTPToken, error) {
	tokenHash := s.hasher.Hash(rawToken)

	t, err := s.store.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}
	if t == nil {
		return nil, ErrTokenNotFound
	}
	if t.Type != expectedType {
		return nil, ErrTokenNotFound
	}
	if t.IsExpired() {
		// Clean up expired token
		_ = s.store.Delete(ctx, t.ID)
		return nil, ErrTokenExpired
	}

	return t, nil
}

// ConsumeToken validates a token and deletes it in one operation.
// This is the typical pattern for one-time use tokens like password reset.
func (s *Service) ConsumeToken(ctx context.Context, rawToken string, expectedType TokenType) (*OTPToken, error) {
	t, err := s.ValidateToken(ctx, rawToken, expectedType)
	if err != nil {
		return nil, err
	}

	// Delete the token (consume it)
	_ = s.store.Delete(ctx, t.ID)

	return t, nil
}

// DeleteTokensForUser deletes all tokens of a specific type for a user.
func (s *Service) DeleteTokensForUser(ctx context.Context, userID string, tokenType TokenType) error {
	return s.store.DeleteByUserAndType(ctx, userID, tokenType)
}

// CleanupExpired removes all expired tokens from the database.
func (s *Service) CleanupExpired(ctx context.Context) error {
	return s.store.DeleteExpired(ctx)
}

// createTokenWithExpiry is the internal method that creates tokens with custom expiry.
func (s *Service) createTokenWithExpiry(ctx context.Context, userID string, tokenType TokenType, identifier *string, expiry time.Duration) (string, error) {
	// Delete any existing tokens of this type for the user
	_ = s.store.DeleteByUserAndType(ctx, userID, tokenType)

	// Generate new token
	rawToken, err := token.Generate()
	if err != nil {
		return "", err
	}

	tokenHash := s.hasher.Hash(rawToken)
	now := time.Now()

	t := &OTPToken{
		ID:         uuid.New().String(),
		UserID:     userID,
		TokenHash:  tokenHash,
		Type:       tokenType,
		Identifier: identifier,
		ExpiresAt:  now.Add(expiry),
		CreatedAt:  now,
	}

	if err := s.store.Create(ctx, t); err != nil {
		return "", err
	}

	return rawToken, nil
}

// expiryForType returns the configured expiry duration for a token type.
func (s *Service) expiryForType(tokenType TokenType) time.Duration {
	switch tokenType {
	case TokenTypePasswordReset:
		return s.config.PasswordResetExpiry
	case TokenTypeEmailVerification:
		return s.config.EmailVerificationExpiry
	case TokenTypeEmailChange:
		return s.config.EmailChangeExpiry
	default:
		return time.Hour // Fallback
	}
}
