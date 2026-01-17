package password_test

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/kv"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/password"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// mockPasswordStore implements password.PasswordStore for testing.
type mockPasswordStore struct {
	mu       sync.RWMutex
	accounts map[string]*password.Account
	sessions map[string][]string // userID -> session IDs
}

func newMockPasswordStore() *mockPasswordStore {
	return &mockPasswordStore{
		accounts: make(map[string]*password.Account),
		sessions: make(map[string][]string),
	}
}

func (m *mockPasswordStore) CreateEmailAccount(ctx context.Context, userID, passwordHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if account already exists
	if _, exists := m.accounts[userID]; exists {
		return errors.New("account already exists")
	}

	m.accounts[userID] = &password.Account{
		ID:           "account-" + userID,
		UserID:       userID,
		Provider:     "email",
		PasswordHash: &passwordHash,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	return nil
}

func (m *mockPasswordStore) GetEmailAccount(ctx context.Context, userID string) (*password.Account, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	account, ok := m.accounts[userID]
	if !ok {
		return nil, nil
	}
	return account, nil
}

func (m *mockPasswordStore) UpdatePassword(ctx context.Context, userID, passwordHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	account, ok := m.accounts[userID]
	if !ok {
		return errors.New("account not found")
	}

	account.PasswordHash = &passwordHash
	account.UpdatedAt = time.Now()
	return nil
}

func (m *mockPasswordStore) DeleteUserSessions(ctx context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.sessions, userID)
	return nil
}

// Helper to add a session for testing
func (m *mockPasswordStore) addSession(userID, sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[userID] = append(m.sessions[userID], sessionID)
}

// mockAuthProvider implements password.AuthProvider for testing.
type mockAuthProvider struct {
	mu       sync.RWMutex
	users    map[string]*plugin.User
	emails   map[string]string // email -> userID
	sessions map[string]*plugin.Session
	baseURL  string
}

func newMockAuthProvider() *mockAuthProvider {
	return &mockAuthProvider{
		users:    make(map[string]*plugin.User),
		emails:   make(map[string]string),
		sessions: make(map[string]*plugin.Session),
		baseURL:  "https://example.com",
	}
}

func (m *mockAuthProvider) GetPluginUserByEmail(ctx context.Context, email string) (*plugin.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	userID, ok := m.emails[email]
	if !ok {
		return nil, models.ErrUserNotFound
	}

	user, ok := m.users[userID]
	if !ok {
		return nil, models.ErrUserNotFound
	}

	return user, nil
}

func (m *mockAuthProvider) CreatePluginUser(ctx context.Context, req plugin.CreateUserRequest) (*plugin.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if email already exists
	if _, exists := m.emails[req.Email]; exists {
		return nil, password.ErrUserAlreadyExists
	}

	userID := "user-" + time.Now().Format("20060102150405.000")
	user := &plugin.User{
		ID:            userID,
		Email:         req.Email,
		EmailVerified: req.EmailVerified,
		Name:          req.Name,
		Image:         req.Image,
		Role:          "user",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	m.users[userID] = user
	m.emails[req.Email] = userID
	return user, nil
}

func (m *mockAuthProvider) CreateSessionForUser(ctx context.Context, userID string, r *http.Request) (*plugin.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sessionID := "session-" + time.Now().Format("20060102150405.000")
	session := &plugin.Session{
		ID:        sessionID,
		UserID:    userID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		RawToken:  "raw-token-" + sessionID,
	}

	m.sessions[sessionID] = session
	return session, nil
}

func (m *mockAuthProvider) VerifyPassword(ctx context.Context, userID, password string) (bool, error) {
	// This is a simplified mock - in real code this would hash and compare
	// For testing, we just return true if the password matches "correct-password"
	return password == "correct-password", nil
}

func (m *mockAuthProvider) BaseURL() string {
	return m.baseURL
}

// Helper to add a user for testing
func (m *mockAuthProvider) addUser(user *plugin.User) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[user.ID] = user
	m.emails[user.Email] = user.ID
}

// mockTokenProvider implements password.PasswordResetTokenProvider for testing.
type mockTokenProvider struct {
	mu     sync.RWMutex
	tokens map[string]string // token -> userID
}

func newMockTokenProvider() *mockTokenProvider {
	return &mockTokenProvider{
		tokens: make(map[string]string),
	}
}

func (m *mockTokenProvider) CreatePasswordResetToken(ctx context.Context, userID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	token := "reset-token-" + time.Now().Format("20060102150405.000")
	m.tokens[token] = userID
	return token, nil
}

func (m *mockTokenProvider) ConsumePasswordResetToken(ctx context.Context, token string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	userID, ok := m.tokens[token]
	if !ok {
		return "", models.ErrVerificationNotFound
	}

	delete(m.tokens, token)
	return userID, nil
}

// mockEventBus implements models.EventBus for testing.
type mockEventBus struct {
	mu     sync.Mutex
	events []models.Event
	nextID models.SubscriptionID
}

func newMockEventBus() *mockEventBus {
	return &mockEventBus{
		events: make([]models.Event, 0),
	}
}

func (m *mockEventBus) Publish(ctx context.Context, event models.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
	return nil
}

func (m *mockEventBus) Subscribe(eventType string, handler models.EventHandler) (models.SubscriptionID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	return m.nextID, nil
}

func (m *mockEventBus) Unsubscribe(eventType string, id models.SubscriptionID) {
	// Not needed for these tests
}

func (m *mockEventBus) Close() error {
	return nil
}

func (m *mockEventBus) GetEvents() []models.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]models.Event{}, m.events...)
}

// testHasher returns a real password hasher for creating valid password hashes in tests.
func testHasher() models.PasswordHasher {
	return models.NewArgon2PasswordHasher()
}

// hashPassword is a helper to generate a valid Argon2id hash for tests.
func hashPassword(t *testing.T, password string) string {
	t.Helper()
	hash, err := testHasher().Hash(password)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	return hash
}

// testDependencies holds all mock dependencies for service tests.
type testDependencies struct {
	store         *mockPasswordStore
	authProvider  *mockAuthProvider
	tokenProvider *mockTokenProvider
	eventBus      *mockEventBus
	kvStore       kv.Store
}

// setupTestService creates a password Service with mock dependencies.
func setupTestService(t *testing.T) (*password.Service, *testDependencies) {
	t.Helper()
	return setupTestServiceWithConfig(t, password.DefaultConfig())
}

// setupTestServiceWithConfig creates a password Service with custom config.
func setupTestServiceWithConfig(t *testing.T, config password.Config) (*password.Service, *testDependencies) {
	t.Helper()

	deps := &testDependencies{
		store:         newMockPasswordStore(),
		authProvider:  newMockAuthProvider(),
		tokenProvider: newMockTokenProvider(),
		eventBus:      newMockEventBus(),
		kvStore:       kv.NewMemoryStore(),
	}

	// Set the kv store for lockout
	config.LockoutStore = deps.kvStore

	service := password.NewService(
		deps.store,
		deps.authProvider,
		deps.tokenProvider,
		deps.eventBus,
		config,
		nil, // logger
	)

	t.Cleanup(func() {
		_ = service.Close()
	})

	return service, deps
}
