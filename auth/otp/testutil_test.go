package otp_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/otp"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/token"
)

// mockTokenStore implements otp.TokenStore for testing
type mockTokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*otp.OTPToken
}

func newMockTokenStore() *mockTokenStore {
	return &mockTokenStore{
		tokens: make(map[string]*otp.OTPToken),
	}
}

func (m *mockTokenStore) Create(ctx context.Context, tok *otp.OTPToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[tok.ID] = tok
	return nil
}

func (m *mockTokenStore) GetByTokenHash(ctx context.Context, tokenHash string) (*otp.OTPToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, tok := range m.tokens {
		if tok.TokenHash == tokenHash {
			return tok, nil
		}
	}
	return nil, nil
}

func (m *mockTokenStore) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tokens, id)
	return nil
}

func (m *mockTokenStore) DeleteByUserAndType(ctx context.Context, userID string, tokenType otp.TokenType) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, tok := range m.tokens {
		if tok.UserID == userID && tok.Type == tokenType {
			delete(m.tokens, id)
		}
	}
	return nil
}

func (m *mockTokenStore) DeleteExpired(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for id, tok := range m.tokens {
		if tok.ExpiresAt.Before(now) {
			delete(m.tokens, id)
		}
	}
	return nil
}

// count returns the number of tokens in the store
func (m *mockTokenStore) count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.tokens)
}

// getAll returns all tokens
func (m *mockTokenStore) getAll() []*otp.OTPToken {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*otp.OTPToken
	for _, tok := range m.tokens {
		result = append(result, tok)
	}
	return result
}

// setupTestService creates a new OTP Service with mock dependencies.
func setupTestService(t *testing.T) (*otp.Service, *mockTokenStore) {
	t.Helper()

	store := newMockTokenStore()
	hasher := token.NewHasher("test-secret")
	config := otp.DefaultConfig()

	service := otp.NewService(store, hasher, config)

	return service, store
}

// setupTestServiceWithConfig creates a new OTP Service with custom config.
func setupTestServiceWithConfig(t *testing.T, config otp.Config) (*otp.Service, *mockTokenStore) {
	t.Helper()

	store := newMockTokenStore()
	hasher := token.NewHasher("test-secret")

	service := otp.NewService(store, hasher, config)

	return service, store
}
