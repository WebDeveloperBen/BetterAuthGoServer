package apikey

import (
	"time"

	"github.com/uptrace/bun"
)

// APIKey represents an API key for programmatic access.
type APIKey struct {
	bun.BaseModel `bun:"table:api_keys,alias:ak"`

	ID        string  `bun:"id,pk" json:"id"`
	Name      *string `bun:"name" json:"name,omitempty"`
	Start     string  `bun:"start,notnull" json:"start"`     // First 6 chars of raw key for UI display
	Prefix    *string `bun:"prefix" json:"prefix,omitempty"` // Optional user prefix (e.g., "myapp")
	Key       string  `bun:"key,notnull" json:"-"`           // Full HMAC-SHA256 hash (never exposed)
	KeyPrefix string  `bun:"key_prefix,notnull" json:"-"`    // First 8 chars of hash for indexed lookup
	UserID    string  `bun:"user_id,notnull" json:"userId"`

	// Rate limiting (fixed window)
	RateLimitEnabled    bool  `bun:"rate_limit_enabled,notnull,default:true" json:"rateLimitEnabled"`
	RateLimitTimeWindow int64 `bun:"rate_limit_time_window" json:"rateLimitTimeWindow,omitempty"` // ms
	RateLimitMax        int   `bun:"rate_limit_max" json:"rateLimitMax,omitempty"`
	RequestCount        int   `bun:"request_count,notnull,default:0" json:"-"` // Current window request count

	// Usage quota
	Remaining      *int       `bun:"remaining" json:"remaining,omitempty"`            // nil = unlimited
	RefillInterval *int64     `bun:"refill_interval" json:"refillInterval,omitempty"` // ms
	RefillAmount   *int       `bun:"refill_amount" json:"refillAmount,omitempty"`
	LastRefillAt   *time.Time `bun:"last_refill_at" json:"lastRefillAt,omitempty"`

	// Status
	Enabled     bool       `bun:"enabled,notnull,default:true" json:"enabled"`
	LastRequest *time.Time `bun:"last_request" json:"lastRequest,omitempty"`
	ExpiresAt   *time.Time `bun:"expires_at" json:"expiresAt,omitempty"`

	// Metadata & permissions (stored as JSON strings)
	Permissions *string `bun:"permissions" json:"-"`
	Metadata    *string `bun:"metadata" json:"-"`

	// Timestamps
	CreatedAt time.Time `bun:"created_at,notnull,default:current_timestamp" json:"createdAt"`
	UpdatedAt time.Time `bun:"updated_at,notnull,default:current_timestamp" json:"updatedAt"`
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
