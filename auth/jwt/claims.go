// Package jwt provides JWT token generation and validation for the auth library.
package jwt

import (
	cryptoRand "crypto/rand"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims represents the JWT claims for access tokens.
type Claims struct {
	jwt.RegisteredClaims

	// UserID is the unique identifier for the user
	UserID string `json:"uid"`

	// SessionID is the unique identifier for the session (optional)
	SessionID string `json:"sid,omitempty"`

	// Email is the user's email address
	Email string `json:"email,omitempty"`

	// Name is the user's display name
	Name string `json:"name,omitempty"`

	// EmailVerified indicates if the user's email is verified
	EmailVerified bool `json:"email_verified,omitempty"`

	// TokenType indicates whether this is an access or refresh token
	TokenType TokenType `json:"type,omitempty"`
}

// TokenType represents the type of JWT token
type TokenType string

const (
	TokenTypeAccess  TokenType = "access"
	TokenTypeRefresh TokenType = "refresh"
)

// NewAccessClaims creates new claims for an access token.
func NewAccessClaims(userID, sessionID, email, name string, emailVerified bool, issuer, audience string, ttl time.Duration) *Claims {
	now := time.Now()
	return &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        generateJTI(),
		},
		UserID:        userID,
		SessionID:     sessionID,
		Email:         email,
		Name:          name,
		EmailVerified: emailVerified,
		TokenType:     TokenTypeAccess,
	}
}

// NewRefreshClaims creates new claims for a refresh token.
func NewRefreshClaims(userID, sessionID, issuer, audience string, ttl time.Duration) *Claims {
	now := time.Now()
	return &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        generateJTI(),
		},
		UserID:    userID,
		SessionID: sessionID,
		TokenType: TokenTypeRefresh,
	}
}

// IsExpired returns true if the token has expired.
func (c *Claims) IsExpired() bool {
	if c.ExpiresAt == nil {
		return false
	}
	return time.Now().After(c.ExpiresAt.Time)
}

// generateJTI generates a unique JWT ID.
func generateJTI() string {
	b := make([]byte, 16)
	_, _ = cryptoRand.Read(b)
	return encodeHex(b)
}

// encodeHex encodes bytes as hex string.
func encodeHex(b []byte) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, len(b)*2)
	for i, v := range b {
		result[i*2] = hexChars[v>>4]
		result[i*2+1] = hexChars[v&0x0f]
	}
	return string(result)
}
