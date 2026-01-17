package apikey

import (
	"time"
)

// APIKey represents an API key for programmatic access.
type APIKey struct {
	ID        string  `json:"id"`
	Name      *string `json:"name,omitempty"`
	Start     string  `json:"start"`            // First 6 chars of raw key for UI display
	Prefix    *string `json:"prefix,omitempty"` // Optional user prefix (e.g., "myapp")
	Key       string  `json:"-"`                // Full HMAC-SHA256 hash (never exposed)
	KeyPrefix string  `json:"-"`                // First 8 chars of hash for indexed lookup
	UserID    string  `json:"userId"`

	// Rate limiting (fixed window)
	RateLimitEnabled    bool  `json:"rateLimitEnabled"`
	RateLimitTimeWindow int64 `json:"rateLimitTimeWindow,omitempty"` // ms
	RateLimitMax        int   `json:"rateLimitMax,omitempty"`
	RequestCount        int   `json:"-"` // Current window request count

	// Usage quota
	Remaining      *int       `json:"remaining,omitempty"`      // nil = unlimited
	RefillInterval *int64     `json:"refillInterval,omitempty"` // ms
	RefillAmount   *int       `json:"refillAmount,omitempty"`
	LastRefillAt   *time.Time `json:"lastRefillAt,omitempty"`

	// Status
	Enabled     bool       `json:"enabled"`
	LastRequest *time.Time `json:"lastRequest,omitempty"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"`

	// Metadata & permissions (stored as JSON strings)
	Permissions *string `json:"-"`
	Metadata    *string `json:"-"`

	// Timestamps
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// Permissions is a map of resource to allowed actions.
// Example: {"files": ["read", "write"], "users": ["read"]}
type Permissions map[string][]string

// HasPermission checks if the given permission is granted.
func (p Permissions) HasPermission(resource, action string) bool {
	if p == nil {
		return false
	}
	actions, ok := p[resource]
	if !ok {
		return false
	}
	for _, a := range actions {
		if a == action || a == "*" {
			return true
		}
	}
	return false
}

// HasAllPermissions checks if all required permissions are granted.
func (p Permissions) HasAllPermissions(required Permissions) bool {
	if required == nil {
		return true
	}
	for resource, actions := range required {
		for _, action := range actions {
			if !p.HasPermission(resource, action) {
				return false
			}
		}
	}
	return true
}

// Metadata is arbitrary key-value data attached to an API key.
type Metadata map[string]any
