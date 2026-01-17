package apikey_test

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/apikey"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/token"
)

// mockKeyStore implements apikey.KeyStore for testing
type mockKeyStore struct {
	mu   sync.RWMutex
	keys map[string]*apikey.APIKey
}

func newMockKeyStore() *mockKeyStore {
	return &mockKeyStore{
		keys: make(map[string]*apikey.APIKey),
	}
}

func (m *mockKeyStore) Create(ctx context.Context, key *apikey.APIKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[key.ID] = key
	return nil
}

func (m *mockKeyStore) GetByID(ctx context.Context, id string) (*apikey.APIKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if key, ok := m.keys[id]; ok {
		return key, nil
	}
	return nil, nil
}

func (m *mockKeyStore) GetByIDAndUser(ctx context.Context, id, userID string) (*apikey.APIKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if key, ok := m.keys[id]; ok && key.UserID == userID {
		return key, nil
	}
	return nil, nil
}

func (m *mockKeyStore) ListByUser(ctx context.Context, userID string) ([]*apikey.APIKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*apikey.APIKey
	for _, key := range m.keys {
		if key.UserID == userID {
			result = append(result, key)
		}
	}
	return result, nil
}

func (m *mockKeyStore) GetByKeyPrefix(ctx context.Context, keyPrefix string) ([]*apikey.APIKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*apikey.APIKey
	for _, key := range m.keys {
		if key.KeyPrefix == keyPrefix && key.Enabled {
			result = append(result, key)
		}
	}
	return result, nil
}

func (m *mockKeyStore) Update(ctx context.Context, key *apikey.APIKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[key.ID] = key
	return nil
}

func (m *mockKeyStore) UpdateUsage(ctx context.Context, key *apikey.APIKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[key.ID] = key
	return nil
}

func (m *mockKeyStore) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.keys, id)
	return nil
}

func (m *mockKeyStore) DeleteAllExpired(ctx context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	var count int64
	for id, key := range m.keys {
		if key.ExpiresAt != nil && key.ExpiresAt.Before(now) {
			delete(m.keys, id)
			count++
		}
	}
	return count, nil
}

// setupTestService creates a new Service with mock dependencies.
func setupTestService(t *testing.T) (*apikey.Service, *mockKeyStore) {
	t.Helper()

	store := newMockKeyStore()
	hasher := token.NewHasher("test-secret")
	config := apikey.DefaultConfig()
	service := apikey.NewService(store, hasher, config, slog.Default())

	t.Cleanup(func() {
		_ = service.Close()
	})

	return service, store
}
