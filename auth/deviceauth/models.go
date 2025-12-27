package deviceauth

import (
	"time"

	"github.com/uptrace/bun"
)

// DeviceCodeStatus represents the status of a device authorization request.
type DeviceCodeStatus string

const (
	// StatusPending indicates the user has not yet approved or denied.
	StatusPending DeviceCodeStatus = "pending"

	// StatusApproved indicates the user approved the request.
	StatusApproved DeviceCodeStatus = "approved"

	// StatusDenied indicates the user denied the request.
	StatusDenied DeviceCodeStatus = "denied"
)

// DeviceCode represents a device authorization request stored in the database.
type DeviceCode struct {
	bun.BaseModel `bun:"table:device_codes,alias:dc"`

	// ID is the primary key.
	ID string `bun:"id,pk"`

	// DeviceCode is the hashed device code (HMAC-SHA256).
	// The raw device code is never stored.
	DeviceCode string `bun:"device_code,notnull"`

	// DeviceCodeHash is the first 8 characters of the hash for indexed lookup.
	DeviceCodeHash string `bun:"device_code_hash,notnull"`

	// UserCode is the human-readable code (e.g., "ABCD-1234").
	// Uses a charset without ambiguous characters (no 0/O, 1/I/L).
	UserCode string `bun:"user_code,notnull,unique"`

	// ClientID is the optional OAuth client identifier.
	ClientID *string `bun:"client_id"`

	// Scope is the requested authorization scopes.
	Scope *string `bun:"scope"`

	// UserID is set when the user approves the request.
	UserID *string `bun:"user_id"`

	// Status is the current state: pending, approved, or denied.
	Status DeviceCodeStatus `bun:"status,notnull"`

	// PollingInterval is the minimum seconds between token polls.
	PollingInterval int `bun:"polling_interval,notnull"`

	// LastPolledAt tracks the last token poll for rate limiting.
	LastPolledAt *time.Time `bun:"last_polled_at"`

	// ExpiresAt is when the device code expires.
	ExpiresAt time.Time `bun:"expires_at,notnull"`

	// CreatedAt is when the device code was created.
	CreatedAt time.Time `bun:"created_at,notnull"`

	// UpdatedAt is when the device code was last updated.
	UpdatedAt time.Time `bun:"updated_at,notnull"`
}

// IsExpired returns true if the device code has expired.
func (dc *DeviceCode) IsExpired() bool {
	return time.Now().After(dc.ExpiresAt)
}

// IsPending returns true if the device code is still pending approval.
func (dc *DeviceCode) IsPending() bool {
	return dc.Status == StatusPending
}

// IsApproved returns true if the device code was approved.
func (dc *DeviceCode) IsApproved() bool {
	return dc.Status == StatusApproved
}

// IsDenied returns true if the device code was denied.
func (dc *DeviceCode) IsDenied() bool {
	return dc.Status == StatusDenied
}

// CanPoll returns true if enough time has passed since the last poll.
func (dc *DeviceCode) CanPoll() bool {
	if dc.LastPolledAt == nil {
		return true
	}
	elapsed := time.Since(*dc.LastPolledAt)
	return elapsed >= time.Duration(dc.PollingInterval)*time.Second
}

// ExpiresInSeconds returns the number of seconds until expiration.
func (dc *DeviceCode) ExpiresInSeconds() int {
	remaining := time.Until(dc.ExpiresAt)
	if remaining < 0 {
		return 0
	}
	return int(remaining.Seconds())
}
