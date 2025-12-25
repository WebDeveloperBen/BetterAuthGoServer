package models

import (
	"context"
	"time"
)

// Verification represents a verification token record
type Verification struct {
	ID         string
	UserID     string
	TokenHash  string
	Type       VerificationType
	Identifier *string // For email_change: new email
	ExpiresAt  time.Time
	CreatedAt  time.Time
}

// IsExpired returns true if the verification has expired
func (v *Verification) IsExpired() bool {
	return time.Now().After(v.ExpiresAt)
}

// VerificationStore defines verification-related database operations
type VerificationStore interface {
	CreateVerification(ctx context.Context, v *Verification) error
	GetVerificationByTokenHash(ctx context.Context, tokenHash string) (*Verification, error)
	DeleteVerification(ctx context.Context, id string) error
	DeleteVerificationsByUserIDAndType(ctx context.Context, userID string, vType VerificationType) error
	DeleteExpiredVerifications(ctx context.Context) error
}
