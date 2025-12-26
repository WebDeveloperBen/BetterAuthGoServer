package models

import (
	"context"
	"encoding/json"
	"time"
)

// Event type constants for the authentication system
const (
	EventUserCreated             = "user.created"
	EventUserUpdated             = "user.updated"
	EventSignedIn                = "user.signed_in"
	EventSignedOut               = "user.signed_out"
	EventPasswordChanged         = "user.password_changed"
	EventPasswordResetRequested  = "user.password_reset_requested"
	EventEmailVerified           = "user.email_verified"
	EventEmailVerificationSent   = "user.email_verification_sent"
	EventOAuthAccountLinked      = "user.oauth_account_linked"
)

// Event represents an auth event to be published or received via the EventBus
type Event struct {
	ID        string            `json:"id"`
	Type      string            `json:"type"`
	Timestamp time.Time         `json:"timestamp"`
	Payload   json.RawMessage   `json:"payload"`
	Metadata  map[string]string `json:"metadata"`
}

// UnmarshalPayload unmarshals the event payload into the provided struct
func (e *Event) UnmarshalPayload(v any) error {
	return json.Unmarshal(e.Payload, v)
}

// EventHandler processes events
type EventHandler func(ctx context.Context, event Event) error

// SubscriptionID identifies a specific event handler subscription for removal
type SubscriptionID uint64

// EventBus combines publisher and subscriber functionality for auth events
type EventBus interface {
	// Publish sends an event to all subscribers
	Publish(ctx context.Context, event Event) error

	// Subscribe registers a handler for a specific event type
	Subscribe(eventType string, handler EventHandler) (SubscriptionID, error)

	// Unsubscribe removes a handler subscription
	Unsubscribe(eventType string, id SubscriptionID)

	// Close shuts down the event bus and cleans up resources
	Close() error
}

// Message represents a message in the pub/sub system
type Message struct {
	UUID     string
	Payload  []byte
	Metadata map[string]string
}

// PubSub is a generic publish-subscribe interface for event transport
type PubSub interface {
	// Publish sends a message to the specified topic
	Publish(ctx context.Context, topic string, msg *Message) error

	// Subscribe returns a channel that receives messages from the specified topic
	Subscribe(ctx context.Context, topic string) (<-chan *Message, error)

	// Close closes the pub/sub and cleans up resources
	Close() error
}

// =============================================================================
// Event Payloads - Typed structs for each event type
// =============================================================================

// UserCreatedPayload is sent when a new user is created
type UserCreatedPayload struct {
	User *User `json:"user"`
}

// UserUpdatedPayload is sent when a user is updated
type UserUpdatedPayload struct {
	User *User `json:"user"`
}

// SignedInPayload is sent after a successful sign in
type SignedInPayload struct {
	User    *User    `json:"user"`
	Session *Session `json:"session"`
}

// SignedOutPayload is sent after a sign out
type SignedOutPayload struct {
	User    *User    `json:"user"`
	Session *Session `json:"session"`
}

// PasswordChangedPayload is sent after a password is changed
type PasswordChangedPayload struct {
	User *User `json:"user"`
}

// PasswordResetRequestedPayload is sent when a password reset is requested
// Token is the raw token that should be sent to the user via email
type PasswordResetRequestedPayload struct {
	User  *User  `json:"user"`
	Token string `json:"token"`
}

// EmailVerifiedPayload is sent after an email is verified
type EmailVerifiedPayload struct {
	User *User `json:"user"`
}

// EmailVerificationSentPayload is sent when email verification is requested
// Token is the raw token that should be sent to the user via email
type EmailVerificationSentPayload struct {
	User  *User  `json:"user"`
	Token string `json:"token"`
}

// OAuthAccountLinkedPayload is sent when an OAuth account is linked to a user
type OAuthAccountLinkedPayload struct {
	User    *User    `json:"user"`
	Account *Account `json:"account"`
}
