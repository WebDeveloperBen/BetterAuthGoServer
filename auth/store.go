package auth

import (
	"context"
	"time"
)

// Store defines the interface for all database operations
// This is implemented by both PostgreSQL and SQLite adapters
type Store interface {
	UserStore
	AccountStore
	SessionStore
	VerificationStore
	OAuthStateStore
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

// ProviderType represents the type of authentication provider
type ProviderType string

const (
	ProviderEmail   ProviderType = "email"
	ProviderGoogle  ProviderType = "google"
	ProviderGitHub  ProviderType = "github"
	ProviderDiscord ProviderType = "discord"
)

// Account represents a linked authentication method for a user
type Account struct {
	ID                    string
	UserID                string
	Provider              ProviderType
	ProviderAccountID     *string
	PasswordHash          *string
	AccessToken           *string
	RefreshToken          *string
	AccessTokenExpiresAt  *time.Time
	RefreshTokenExpiresAt *time.Time
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// AccountStore defines account-related database operations
type AccountStore interface {
	CreateAccount(ctx context.Context, account *Account) error
	GetAccountByID(ctx context.Context, id string) (*Account, error)
	GetAccountByUserIDAndProvider(ctx context.Context, userID string, provider ProviderType) (*Account, error)
	GetAccountByProvider(ctx context.Context, provider ProviderType, providerAccountID string) (*Account, error)
	ListAccountsByUserID(ctx context.Context, userID string) ([]*Account, error)
	UpdateAccount(ctx context.Context, account *Account) error
	DeleteAccount(ctx context.Context, id string) error
	DeleteAccountsByUserID(ctx context.Context, userID string) error
}

// Session represents an authenticated user session
type Session struct {
	ID        string
	UserID    string
	TokenHash string
	IPAddress *string
	UserAgent *string
	CreatedAt time.Time
	ExpiresAt time.Time
	LastUsed  time.Time

	// RawToken is not persisted - only set on creation
	RawToken string
}

// IsExpired returns true if the session has expired
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// SessionStore defines session-related database operations
type SessionStore interface {
	CreateSession(ctx context.Context, session *Session) error
	GetSessionByID(ctx context.Context, id string) (*Session, error)
	GetSessionByTokenHash(ctx context.Context, tokenHash string) (*Session, error)
	ListSessionsByUserID(ctx context.Context, userID string) ([]*Session, error)
	UpdateSessionLastUsed(ctx context.Context, id string) error
	DeleteSession(ctx context.Context, id string) error
	DeleteSessionsByUserID(ctx context.Context, userID string) error
	DeleteExpiredSessions(ctx context.Context) error
}

// VerificationType represents the type of verification token
type VerificationType string

const (
	VerificationTypeEmail         VerificationType = "email_verification"
	VerificationTypePasswordReset VerificationType = "password_reset"
	VerificationTypeEmailChange   VerificationType = "email_change"
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

// OAuthState represents an OAuth state for CSRF protection
type OAuthState struct {
	State      string
	Provider   string
	Verifier   *string // PKCE verifier
	RedirectTo *string
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// OAuthStateStore defines OAuth state-related database operations
type OAuthStateStore interface {
	CreateOAuthState(ctx context.Context, state *OAuthState) error
	GetOAuthState(ctx context.Context, state string) (*OAuthState, error)
	DeleteOAuthState(ctx context.Context, state string) error
	DeleteExpiredOAuthStates(ctx context.Context) error
}

// ListUsersOptions contains options for listing users
type ListUsersOptions struct {
	Offset int
	Limit  int
	Query  string // Optional search query
	Role   string // Filter by role
}

// ListUsersResult contains the result of listing users
type ListUsersResult struct {
	Users []*User
	Total int64
}

// AdminStore defines admin-related database operations.
// This interface is optional - stores can implement it to enable admin features.
type AdminStore interface {
	// ListUsers returns a paginated list of users
	ListUsers(ctx context.Context, opts ListUsersOptions) (*ListUsersResult, error)

	// BanUser bans a user with an optional reason
	BanUser(ctx context.Context, userID string, reason string) error

	// UnbanUser removes a ban from a user
	UnbanUser(ctx context.Context, userID string) error

	// SetUserRole sets the role for a user
	SetUserRole(ctx context.Context, userID string, role string) error

	// CountUsers returns the total number of users
	CountUsers(ctx context.Context) (int64, error)
}
