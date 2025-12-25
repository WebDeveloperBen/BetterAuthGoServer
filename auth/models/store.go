package models

// Store defines the interface for all database operations.
// This is a composite interface that embeds all domain-specific stores.
// It is implemented by both PostgreSQL and SQLite adapters.
type Store interface {
	UserStore
	AccountStore
	SessionStore
	VerificationStore
	OAuthStateStore
}
