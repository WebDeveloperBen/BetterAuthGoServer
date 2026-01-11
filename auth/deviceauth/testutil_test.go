package deviceauth_test

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/deviceauth"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/token"
)

// normalizeUserCode removes hyphens from user codes to match SQL behavior
func normalizeUserCode(code string) string {
	return strings.ReplaceAll(code, "-", "")
}

// mockDeviceCodeStore implements deviceauth.DeviceCodeStore for testing
type mockDeviceCodeStore struct {
	mu    sync.RWMutex
	codes map[string]*deviceauth.DeviceCode
}

func newMockDeviceCodeStore() *mockDeviceCodeStore {
	return &mockDeviceCodeStore{
		codes: make(map[string]*deviceauth.DeviceCode),
	}
}

func (m *mockDeviceCodeStore) CreateDeviceCode(ctx context.Context, code *deviceauth.DeviceCode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codes[code.ID] = code
	return nil
}

func (m *mockDeviceCodeStore) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*deviceauth.DeviceCode, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	normalizedInput := normalizeUserCode(userCode)
	for _, code := range m.codes {
		// Match normalized user codes like the SQL: REPLACE(user_code, '-', '') = REPLACE(?, '-', '')
		if normalizeUserCode(code.UserCode) == normalizedInput {
			return code, nil
		}
	}
	return nil, nil
}

func (m *mockDeviceCodeStore) GetDeviceCodeByHash(ctx context.Context, hashPrefix, fullHash string) (*deviceauth.DeviceCode, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, code := range m.codes {
		// Match by hash prefix first (indexed lookup), then verify full hash
		if code.DeviceCodeHash == hashPrefix && code.DeviceCode == fullHash {
			return code, nil
		}
	}
	return nil, nil
}

func (m *mockDeviceCodeStore) UpdateDeviceCodeStatus(ctx context.Context, id, status string, userID *string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if code, ok := m.codes[id]; ok {
		code.Status = deviceauth.DeviceCodeStatus(status)
		code.UserID = userID
		code.UpdatedAt = time.Now()
		return nil
	}
	return fmt.Errorf("device code not found")
}

func (m *mockDeviceCodeStore) UpdateDeviceCodeLastPolled(ctx context.Context, id string, lastPolledAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if code, ok := m.codes[id]; ok {
		code.LastPolledAt = &lastPolledAt
		code.UpdatedAt = time.Now()
		return nil
	}
	return fmt.Errorf("device code not found")
}

func (m *mockDeviceCodeStore) DeleteExpiredDeviceCodes(ctx context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	var count int64
	for id, code := range m.codes {
		if code.ExpiresAt.Before(now) {
			delete(m.codes, id)
			count++
		}
	}
	return count, nil
}

func (m *mockDeviceCodeStore) DeleteDeviceCode(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.codes, id)
	return nil
}

// mockAuthProvider implements AuthProvider and AuthCore for testing
type mockAuthProvider struct {
	mu               sync.RWMutex
	users            map[string]*plugin.User
	sessions         map[string]*plugin.Session
	currentUser      *plugin.User
	createSessionErr error
}

func newMockAuthProvider() *mockAuthProvider {
	return &mockAuthProvider{
		users:    make(map[string]*plugin.User),
		sessions: make(map[string]*plugin.Session),
	}
}

// AuthCore interface methods
func (m *mockAuthProvider) BaseURL() string {
	return "https://example.com"
}

func (m *mockAuthProvider) Secret() string {
	return "test-secret-key-32-chars-long!!!"
}

func (m *mockAuthProvider) GetPluginUser(ctx context.Context, userID string) (*plugin.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if user, ok := m.users[userID]; ok {
		return user, nil
	}
	return nil, fmt.Errorf("user not found")
}

func (m *mockAuthProvider) CreateSessionForUser(ctx context.Context, userID string, r *http.Request) (*plugin.Session, error) {
	if m.createSessionErr != nil {
		return nil, m.createSessionErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	session := &plugin.Session{
		ID:        fmt.Sprintf("session-%d", len(m.sessions)+1),
		UserID:    userID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		RawToken:  "test-token",
	}
	m.sessions[session.ID] = session
	return session, nil
}

func (m *mockAuthProvider) GetUserFromRequest(r *http.Request) (*plugin.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.currentUser == nil {
		return nil, fmt.Errorf("no user in request")
	}
	return m.currentUser, nil
}

// createTestService creates a service for testing with mock store
func createTestService(t *testing.T, store deviceauth.DeviceCodeStore, opts ...deviceauth.Option) *deviceauth.Service {
	t.Helper()

	config := deviceauth.DefaultConfig()
	config.VerificationURI = "https://example.com/device"
	config.CleanupInterval = 0 // Disable cleanup for tests

	for _, opt := range opts {
		opt(&config)
	}

	hasher := token.NewHasher("test-secret-key-32-chars-long!!!")

	return deviceauth.NewService(store, hasher, config, slog.Default())
}

// createTestPlugin creates a plugin for testing
func createTestPlugin(t *testing.T, store deviceauth.DeviceCodeStore, auth *mockAuthProvider, opts ...deviceauth.Option) *deviceauth.Plugin {
	t.Helper()

	p := deviceauth.NewPlugin(opts...)

	hasher := token.NewHasher("test-secret-key-32-chars-long!!!")

	ctx := plugin.Context{
		Store:   nil, // Store is not used directly in tests with mock
		BaseURL: "https://example.com",
		Secret:  "test-secret-key-32-chars-long!!!",
		Auth:    auth,
		Hasher:  hasher,
		Logger:  slog.Default(),
	}

	if err := p.Init(ctx); err != nil {
		t.Fatalf("Failed to initialize plugin: %v", err)
	}

	return p
}
