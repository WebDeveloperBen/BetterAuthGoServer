package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/config"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/oauth"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/oauth/providers"
)

// mockStore implements models.Store for testing
type mockStore struct {
	users        map[string]*models.User
	sessions     map[string]*models.Session
	accounts     map[string]*models.Account
	verification map[string]*models.Verification
}

func newMockStore() *mockStore {
	return &mockStore{
		users:        make(map[string]*models.User),
		sessions:     make(map[string]*models.Session),
		accounts:     make(map[string]*models.Account),
		verification: make(map[string]*models.Verification),
	}
}

// User methods
func (m *mockStore) CreateUser(ctx context.Context, user *models.User) error {
	m.users[user.ID] = user
	return nil
}

func (m *mockStore) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	return m.users[id], nil
}

func (m *mockStore) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	for _, u := range m.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, nil
}

func (m *mockStore) UpdateUser(ctx context.Context, user *models.User) error {
	m.users[user.ID] = user
	return nil
}

func (m *mockStore) SetEmailVerified(ctx context.Context, userID string, verified bool) error {
	if u, ok := m.users[userID]; ok {
		u.EmailVerified = verified
		u.UpdatedAt = time.Now()
	}
	return nil
}

func (m *mockStore) DeleteUser(ctx context.Context, id string) error {
	delete(m.users, id)
	return nil
}

// Session methods
func (m *mockStore) CreateSession(ctx context.Context, session *models.Session) error {
	m.sessions[session.TokenHash] = session
	return nil
}

func (m *mockStore) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*models.Session, error) {
	return m.sessions[tokenHash], nil
}

func (m *mockStore) GetSessionByID(ctx context.Context, id string) (*models.Session, error) {
	for _, s := range m.sessions {
		if s.ID == id {
			return s, nil
		}
	}
	return nil, nil
}

func (m *mockStore) ListSessionsByUserID(ctx context.Context, userID string) ([]*models.Session, error) {
	var sessions []*models.Session
	for _, s := range m.sessions {
		if s.UserID == userID {
			sessions = append(sessions, s)
		}
	}
	return sessions, nil
}

func (m *mockStore) UpdateSessionLastUsed(ctx context.Context, id string) error {
	for _, s := range m.sessions {
		if s.ID == id {
			s.LastUsed = time.Now()
			break
		}
	}
	return nil
}

func (m *mockStore) DeleteSession(ctx context.Context, id string) error {
	for hash, s := range m.sessions {
		if s.ID == id {
			delete(m.sessions, hash)
			break
		}
	}
	return nil
}

func (m *mockStore) DeleteSessionsByUserID(ctx context.Context, userID string) error {
	for hash, s := range m.sessions {
		if s.UserID == userID {
			delete(m.sessions, hash)
		}
	}
	return nil
}

func (m *mockStore) DeleteExpiredSessions(ctx context.Context) error {
	return nil
}

// Account methods
func (m *mockStore) CreateAccount(ctx context.Context, account *models.Account) error {
	m.accounts[account.ID] = account
	return nil
}

func (m *mockStore) GetAccountByID(ctx context.Context, id string) (*models.Account, error) {
	return m.accounts[id], nil
}

func (m *mockStore) GetAccountByUserIDAndProvider(ctx context.Context, userID string, provider models.ProviderType) (*models.Account, error) {
	for _, a := range m.accounts {
		if a.UserID == userID && a.Provider == provider {
			return a, nil
		}
	}
	return nil, nil
}

func (m *mockStore) GetAccountByProvider(ctx context.Context, provider models.ProviderType, providerAccountID string) (*models.Account, error) {
	for _, a := range m.accounts {
		if a.Provider == provider && a.ProviderAccountID != nil && *a.ProviderAccountID == providerAccountID {
			return a, nil
		}
	}
	return nil, nil
}

func (m *mockStore) ListAccountsByUserID(ctx context.Context, userID string) ([]*models.Account, error) {
	var accounts []*models.Account
	for _, a := range m.accounts {
		if a.UserID == userID {
			accounts = append(accounts, a)
		}
	}
	return accounts, nil
}

func (m *mockStore) UpdateAccount(ctx context.Context, account *models.Account) error {
	m.accounts[account.ID] = account
	return nil
}

func (m *mockStore) DeleteAccount(ctx context.Context, id string) error {
	delete(m.accounts, id)
	return nil
}

func (m *mockStore) DeleteAccountsByUserID(ctx context.Context, userID string) error {
	for id, a := range m.accounts {
		if a.UserID == userID {
			delete(m.accounts, id)
		}
	}
	return nil
}

// Verification methods
func (m *mockStore) CreateVerification(ctx context.Context, v *models.Verification) error {
	m.verification[v.TokenHash] = v
	return nil
}

func (m *mockStore) GetVerificationByTokenHash(ctx context.Context, tokenHash string) (*models.Verification, error) {
	return m.verification[tokenHash], nil
}

func (m *mockStore) DeleteVerification(ctx context.Context, id string) error {
	for hash, v := range m.verification {
		if v.ID == id {
			delete(m.verification, hash)
			break
		}
	}
	return nil
}

func (m *mockStore) DeleteExpiredVerifications(ctx context.Context) error {
	return nil
}

func (m *mockStore) DeleteVerificationsByUserIDAndType(ctx context.Context, userID string, vType models.VerificationType) error {
	for hash, v := range m.verification {
		if v.UserID == userID && v.Type == vType {
			delete(m.verification, hash)
		}
	}
	return nil
}

// Admin methods
func (m *mockStore) ListUsers(ctx context.Context, opts models.ListUsersOptions) (*models.ListUsersResult, error) {
	var users []*models.User
	for _, u := range m.users {
		users = append(users, u)
	}
	return &models.ListUsersResult{Users: users, Total: int64(len(users))}, nil
}

func (m *mockStore) BanUser(ctx context.Context, userID string, reason string) error {
	if u, ok := m.users[userID]; ok {
		u.Banned = true
		now := time.Now()
		u.BannedAt = &now
		if reason != "" {
			u.BanReason = &reason
		}
	}
	return nil
}

func (m *mockStore) UnbanUser(ctx context.Context, userID string) error {
	if u, ok := m.users[userID]; ok {
		u.Banned = false
		u.BannedAt = nil
		u.BanReason = nil
	}
	return nil
}

func (m *mockStore) SetUserRole(ctx context.Context, userID string, role string) error {
	if u, ok := m.users[userID]; ok {
		u.Role = role
	}
	return nil
}

func (m *mockStore) CountUsers(ctx context.Context) (int64, error) {
	return int64(len(m.users)), nil
}

// Helper to create auth instance
func createTestAuth(t *testing.T) (*auth.Auth, *mockStore) {
	t.Helper()
	store := newMockStore()

	a, err := auth.New(store,
		config.WithSecret("test-secret-32-bytes-long-here!!"),
		config.WithBaseURL("http://localhost:3000"),
		config.WithSessionCleanupInterval(0),
		config.WithCSRF(false),
		config.WithPasswordComplexity(false),
	)
	if err != nil {
		t.Fatalf("Failed to create auth: %v", err)
	}

	return a, store
}

func TestOAuthProviders(t *testing.T) {
	// Skip this test when using mock store - OAuth plugin requires real database access.
	// The OAuth plugin is disabled when no DBProvider is available (ctx.RawDB is nil).
	// For a proper integration test, see examples/with-oauth or use a real database.
	t.Skip("OAuth plugin requires DBProvider (real database) - skipping with mock store")

	a, _ := createTestAuth(t)
	defer a.Close()

	// OAuth is now a plugin - register it with a provider to test
	oauthPlugin := oauth.NewPlugin(
		providers.NewGoogle("test-client-id", "test-client-secret", "http://localhost/oauth/google/callback"),
	)
	a.Use(oauthPlugin)
	if err := a.Err(); err != nil {
		t.Fatalf("Failed to register OAuth plugin: %v", err)
	}

	router := a.Handler()

	req := httptest.NewRequest("GET", "/oauth/providers", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}

	var response map[string][]string
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["providers"] == nil {
		t.Error("Expected providers in response")
	}

	// Verify google provider is in the list
	found := slices.Contains(response["providers"], "google")
	if !found {
		t.Error("Expected 'google' in providers list")
	}
}

func TestProfileEndpointRequiresAuth(t *testing.T) {
	a, _ := createTestAuth(t)
	defer a.Close()

	router := a.Handler()

	req := httptest.NewRequest("GET", "/profile", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}
