package models

import (
	"context"
	"strings"
	"time"
)

// NormalizeEmail returns the canonical form in which emails are stored and looked up:
// surrounding whitespace removed and lower-cased, so addresses differing only in case
// identify the same user.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// User represents an authenticated user
type User struct {
	ID            string
	Email         string
	EmailVerified bool
	Name          string
	Image         *string
	Banned        bool       // Whether the user is banned
	BannedAt      *time.Time // When the user was banned
	BanReason     *string    // Reason for the ban
	Role          string     // User role (e.g., "user", "admin")
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// UserStore defines user-related database operations
type UserStore interface {
	CreateUser(ctx context.Context, user *User) error
	GetUserByID(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	UpdateUser(ctx context.Context, user *User) error
	SetEmailVerified(ctx context.Context, userID string, verified bool) error
	DeleteUser(ctx context.Context, id string) error
}
