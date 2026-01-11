package anonymous_test

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/anonymous"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// mockAnonymousStore implements anonymous.AnonymousStore for testing
type mockAnonymousStore struct {
	mu    sync.RWMutex
	users map[string]*mockUserRecord
}

type mockUserRecord struct {
	ID            string
	Email         string
	EmailVerified bool
	Name          string
	Image         *string
	Role          string
	Banned        bool
	IsAnonymous   bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func newMockAnonymousStore() *mockAnonymousStore {
	return &mockAnonymousStore{
		users: make(map[string]*mockUserRecord),
	}
}

func (m *mockAnonymousStore) SetAnonymousFlag(ctx context.Context, userID string, isAnonymous bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if user, ok := m.users[userID]; ok {
		user.IsAnonymous = isAnonymous
		user.UpdatedAt = time.Now()
		return nil
	}

	// Create a placeholder user if not exists (this simulates the DB behavior)
	m.users[userID] = &mockUserRecord{
		ID:          userID,
		IsAnonymous: isAnonymous,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	return nil
}

func (m *mockAnonymousStore) DeleteStaleAnonymousUsers(ctx context.Context, cutoff time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var deleted int64
	for id, user := range m.users {
		if user.IsAnonymous && user.CreatedAt.Before(cutoff) {
			delete(m.users, id)
			deleted++
		}
	}
	return deleted, nil
}

func (m *mockAnonymousStore) EnsureAnonymousColumn(ctx context.Context) error {
	return nil
}

func (m *mockAnonymousStore) GetUserAnonymousStatus(ctx context.Context, userID string) (*anonymous.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	user, ok := m.users[userID]
	if !ok {
		return nil, nil
	}

	return &anonymous.User{
		ID:            user.ID,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Name:          user.Name,
		Image:         user.Image,
		Role:          user.Role,
		Banned:        user.Banned,
		IsAnonymous:   user.IsAnonymous,
		CreatedAt:     user.CreatedAt,
		UpdatedAt:     user.UpdatedAt,
	}, nil
}

func (m *mockAnonymousStore) addUser(id, email, name string, isAnonymous bool, createdAt time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.users[id] = &mockUserRecord{
		ID:          id,
		Email:       email,
		Name:        name,
		Role:        "user",
		IsAnonymous: isAnonymous,
		CreatedAt:   createdAt,
		UpdatedAt:   createdAt,
	}
}

func (m *mockAnonymousStore) getUser(id string) *mockUserRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.users[id]
}

// mockAuthProvider implements the AuthProvider interface for testing
type mockAuthProvider struct {
	mu               sync.RWMutex
	users            map[string]*plugin.User
	sessions         map[string]*plugin.Session
	currentUser      *plugin.User
	createUserFunc   func(ctx context.Context, req plugin.CreateUserRequest) (*plugin.User, error)
	createSessionErr error
	deleteUserErr    error
	deletedUsers     []string
}

func newMockAuthProvider() *mockAuthProvider {
	return &mockAuthProvider{
		users:        make(map[string]*plugin.User),
		sessions:     make(map[string]*plugin.Session),
		deletedUsers: []string{},
	}
}

func (m *mockAuthProvider) GetPluginUser(ctx context.Context, userID string) (*plugin.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if user, ok := m.users[userID]; ok {
		return user, nil
	}
	return nil, fmt.Errorf("user not found")
}

func (m *mockAuthProvider) GetPluginUserByEmail(ctx context.Context, email string) (*plugin.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, user := range m.users {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

func (m *mockAuthProvider) CreatePluginUser(ctx context.Context, req plugin.CreateUserRequest) (*plugin.User, error) {
	if m.createUserFunc != nil {
		return m.createUserFunc(ctx, req)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	user := &plugin.User{
		ID:            fmt.Sprintf("user-%d", len(m.users)+1),
		Email:         req.Email,
		Name:          req.Name,
		EmailVerified: req.EmailVerified,
		Image:         req.Image,
		Role:          "user",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	m.users[user.ID] = user
	return user, nil
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

func (m *mockAuthProvider) DeleteUser(ctx context.Context, userID string) error {
	if m.deleteUserErr != nil {
		return m.deleteUserErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.users, userID)
	m.deletedUsers = append(m.deletedUsers, userID)
	return nil
}

func (m *mockAuthProvider) GetUserFromRequest(r *http.Request) (*plugin.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.currentUser == nil {
		return nil, fmt.Errorf("no user in request")
	}
	return m.currentUser, nil
}

// createTestService creates a service for testing with mocked dependencies
func createTestService(t *testing.T, store anonymous.AnonymousStore, auth anonymous.AuthProvider, opts ...anonymous.Option) *anonymous.Service {
	t.Helper()
	config := anonymous.DefaultConfig()
	for _, opt := range opts {
		opt(&config)
	}
	return anonymous.NewService(store, auth, config, slog.Default())
}
