package otp

import (
	"time"

	"github.com/uptrace/bun"
)

// TokenType represents the type of OTP token
type TokenType string

const (
	TokenTypePasswordReset     TokenType = "password_reset"
	TokenTypeEmailVerification TokenType = "email_verification"
	TokenTypeEmailChange       TokenType = "email_change"
)

// OTPToken represents an OTP token record in the database.
// These are one-time use tokens for verification flows like password reset and email verification.
type OTPToken struct {
	bun.BaseModel `bun:"table:otp_tokens,alias:ot"`

	ID         string    `bun:"id,pk"`
	UserID     string    `bun:"user_id,notnull"`
	TokenHash  string    `bun:"token_hash,notnull"`
	Type       TokenType `bun:"type,notnull"`
	Identifier *string   `bun:"identifier"` // For email_change: new email address
	ExpiresAt  time.Time `bun:"expires_at,notnull"`
	CreatedAt  time.Time `bun:"created_at,notnull"`
}

// TableName returns the table name
func (t *OTPToken) TableName() string {
	return "otp_tokens"
}

// IsExpired returns true if the token has expired
func (t *OTPToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}
