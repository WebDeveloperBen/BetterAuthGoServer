package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/handlers"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
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

// OAuth state methods
func (m *mockStore) CreateOAuthState(ctx context.Context, state *models.OAuthState) error {
	return nil
}

func (m *mockStore) GetOAuthState(ctx context.Context, state string) (*models.OAuthState, error) {
	return nil, nil
}

func (m *mockStore) DeleteOAuthState(ctx context.Context, state string) error {
	return nil
}

func (m *mockStore) DeleteExpiredOAuthStates(ctx context.Context) error {
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
		auth.WithSecret("test-secret-32-bytes-long-here!!"),
		auth.WithBaseURL("http://localhost:3000"),
		auth.WithSessionCleanupInterval(0),
		auth.WithCSRF(false),
		auth.WithPasswordComplexity(false),
	)
	if err != nil {
		t.Fatalf("Failed to create auth: %v", err)
	}

	return a, store
}

func TestSignUp(t *testing.T) {
	a, _ := createTestAuth(t)
	defer a.Close()

	router := handlers.NewRouter(a)

	body := `{"email":"test@example.com","password":"password123","name":"Test User"}`
	req := httptest.NewRequest("POST", "/sign-up", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("Status = %d, want %d. Body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["user"] == nil {
		t.Error("Expected user in response")
	}
}

func TestSignIn(t *testing.T) {
	a, store := createTestAuth(t)
	defer a.Close()

	// First sign up a user
	_, _, err := a.SignUp(context.Background(), auth.SignUpRequest{
		Email:    "test@example.com",
		Password: "password123",
		Name:     "Test User",
	}, nil)
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}

	// Verify user exists
	if len(store.users) == 0 {
		t.Fatal("No users in store after signup")
	}

	router := handlers.NewRouter(a)

	body := `{"email":"test@example.com","password":"password123"}`
	req := httptest.NewRequest("POST", "/sign-in", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d. Body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	// Check that session cookie was set
	cookies := rec.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "session" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected session cookie to be set")
	}
}

func TestSignInInvalidCredentials(t *testing.T) {
	a, _ := createTestAuth(t)
	defer a.Close()

	router := handlers.NewRouter(a)

	body := `{"email":"nonexistent@example.com","password":"wrongpassword"}`
	req := httptest.NewRequest("POST", "/sign-in", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestOAuthProviders(t *testing.T) {
	a, _ := createTestAuth(t)
	defer a.Close()

	router := handlers.NewRouter(a)

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
}

func TestPasswordReset(t *testing.T) {
	a, _ := createTestAuth(t)
	defer a.Close()

	// Sign up a user first
	_, _, _ = a.SignUp(context.Background(), auth.SignUpRequest{
		Email:    "test@example.com",
		Password: "password123",
		Name:     "Test User",
	}, nil)

	router := handlers.NewRouter(a)

	// Request password reset - should always return 204 to prevent enumeration
	body := `{"email":"test@example.com"}`
	req := httptest.NewRequest("POST", "/password/reset", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestPasswordResetNonExistentUser(t *testing.T) {
	a, _ := createTestAuth(t)
	defer a.Close()

	router := handlers.NewRouter(a)

	// Request password reset for non-existent user - should still return 204
	body := `{"email":"nonexistent@example.com"}`
	req := httptest.NewRequest("POST", "/password/reset", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	// Should return 204 to prevent user enumeration
	if rec.Code != http.StatusNoContent {
		t.Errorf("Status = %d, want %d (to prevent user enumeration)", rec.Code, http.StatusNoContent)
	}
}

func TestAdminEndpointRequiresAuth(t *testing.T) {
	a, _ := createTestAuth(t)
	defer a.Close()

	router := handlers.NewRouter(a)

	req := httptest.NewRequest("GET", "/admin/users", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestProfileEndpointRequiresAuth(t *testing.T) {
	a, _ := createTestAuth(t)
	defer a.Close()

	router := handlers.NewRouter(a)

	req := httptest.NewRequest("GET", "/profile", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}
