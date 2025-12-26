package password

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/kv"
)

// Lockout error
var ErrAccountLocked = errors.New("password: account is temporarily locked due to too many failed login attempts")

// lockoutPrefix is the key prefix for lockout-related data
const lockoutPrefix = "lockout:"

// lockoutService tracks failed login attempts and manages account lockouts.
type lockoutService struct {
	store     kv.Store
	threshold int
	duration  time.Duration
	ownsStore bool // true if we created the store and should close it
}

// newLockoutService creates a new lockout service.
// If store is nil, creates an in-memory store.
func newLockoutService(store kv.Store, threshold int, duration time.Duration) *lockoutService {
	ownsStore := false
	if store == nil {
		store = kv.NewMemoryStore()
		ownsStore = true
	}

	return &lockoutService{
		store:     store,
		threshold: threshold,
		duration:  duration,
		ownsStore: ownsStore,
	}
}

// isEnabled returns true if lockout is enabled (threshold > 0)
func (l *lockoutService) isEnabled() bool {
	return l.threshold > 0
}

// attemptsKey returns the kv key for tracking failed attempts
func (l *lockoutService) attemptsKey(email string) string {
	return lockoutPrefix + "attempts:" + email
}

// lockedKey returns the kv key for the lockout flag
func (l *lockoutService) lockedKey(email string) string {
	return lockoutPrefix + "locked:" + email
}

// IsLocked checks if an account is currently locked.
func (l *lockoutService) IsLocked(ctx context.Context, email string) (bool, error) {
	if !l.isEnabled() {
		return false, nil
	}

	exists, err := l.store.Exists(ctx, l.lockedKey(email))
	if err != nil {
		return false, fmt.Errorf("lockout check failed: %w", err)
	}
	return exists, nil
}

// RecordFailure records a failed login attempt.
// Returns true if the account is now locked after this failure.
func (l *lockoutService) RecordFailure(ctx context.Context, email string) (bool, error) {
	if !l.isEnabled() {
		return false, nil
	}

	attemptsKey := l.attemptsKey(email)

	// Increment failure count
	count, err := l.store.Increment(ctx, attemptsKey, 1)
	if err != nil {
		return false, fmt.Errorf("failed to record login failure: %w", err)
	}

	// Set TTL on first attempt (so it auto-expires)
	if count == 1 {
		// Use the lockout duration as the window for counting attempts
		if err := l.store.Expire(ctx, attemptsKey, l.duration); err != nil {
			// Non-fatal, continue
		}
	}

	// Check if we've exceeded the threshold
	if int(count) >= l.threshold {
		// Lock the account
		if err := l.store.Set(ctx, l.lockedKey(email), []byte("1"), l.duration); err != nil {
			return false, fmt.Errorf("failed to lock account: %w", err)
		}
		// Clear the attempts counter since we're now locked
		_ = l.store.Delete(ctx, attemptsKey)
		return true, nil
	}

	return false, nil
}

// ClearFailures clears the failure count for an account (called on successful login).
func (l *lockoutService) ClearFailures(ctx context.Context, email string) error {
	if !l.isEnabled() {
		return nil
	}

	// Delete both the attempts counter and any lockout
	_ = l.store.Delete(ctx, l.attemptsKey(email))
	_ = l.store.Delete(ctx, l.lockedKey(email))
	return nil
}

// Close releases resources held by the lockout service.
func (l *lockoutService) Close() error {
	if l.ownsStore && l.store != nil {
		return l.store.Close()
	}
	return nil
}
