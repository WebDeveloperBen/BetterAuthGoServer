package jwt

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/kv"
)

// ErrAccountLocked is returned when an account is temporarily locked due to too many failed attempts.
var ErrAccountLocked = errors.New("jwt: account is temporarily locked due to too many failed login attempts")

const jwtLockoutPrefix = "jwt_lockout:"

type lockoutService struct {
	store     kv.Store
	threshold int
	duration  time.Duration
	ownsStore bool
}

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

func (l *lockoutService) isEnabled() bool {
	return l.threshold > 0
}

func (l *lockoutService) attemptsKey(email string) string {
	return jwtLockoutPrefix + "attempts:" + email
}

func (l *lockoutService) lockedKey(email string) string {
	return jwtLockoutPrefix + "locked:" + email
}

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

func (l *lockoutService) RecordFailure(ctx context.Context, email string) (bool, error) {
	if !l.isEnabled() {
		return false, nil
	}

	attemptsKey := l.attemptsKey(email)
	count, err := l.store.Increment(ctx, attemptsKey, 1)
	if err != nil {
		return false, fmt.Errorf("failed to record login failure: %w", err)
	}

	if count == 1 {
		_ = l.store.Expire(ctx, attemptsKey, l.duration)
	}

	if int(count) >= l.threshold {
		if err := l.store.Set(ctx, l.lockedKey(email), []byte("1"), l.duration); err != nil {
			return false, fmt.Errorf("failed to lock account: %w", err)
		}
		_ = l.store.Delete(ctx, attemptsKey)
		return true, nil
	}

	return false, nil
}

func (l *lockoutService) ClearFailures(ctx context.Context, email string) error {
	if !l.isEnabled() {
		return nil
	}
	_ = l.store.Delete(ctx, l.attemptsKey(email))
	_ = l.store.Delete(ctx, l.lockedKey(email))
	return nil
}

func (l *lockoutService) Close() error {
	if l.ownsStore && l.store != nil {
		return l.store.Close()
	}
	return nil
}
