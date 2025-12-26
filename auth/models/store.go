package models

// Store defines the interface for all database operations.
// This is a composite interface that embeds all domain-specific stores.
// It is implemented by both PostgreSQL and SQLite adapters.
//
// Note: OAuth-specific operations (oauth_states, oauth_accounts) are managed
// by the OAuth plugin directly, not through this interface.
type Store interface {
	UserStore
	AccountStore
	SessionStore
	VerificationStore
}
