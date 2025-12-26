package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/config"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/token"
)

// mockAdminStore extends mockStoreForMiddleware with AdminStore methods
type mockAdminStore struct {
	*mockStoreForMiddleware
}

func newMockAdminStore() *mockAdminStore {
	return &mockAdminStore{
		mockStoreForMiddleware: newMockStoreForMiddleware(),
	}
}

func (m *mockAdminStore) ListUsers(ctx context.Context, opts models.ListUsersOptions) (*models.ListUsersResult, error) {
	var users []*models.User
	for _, u := range m.users {
		users = append(users, u)
	}
	return &models.ListUsersResult{
		Users: users,
		Total: int64(len(users)),
	}, nil
}

func (m *mockAdminStore) BanUser(ctx context.Context, userID string, reason string) error {
	if user, ok := m.users[userID]; ok {
		user.Banned = true
		now := time.Now()
		user.BannedAt = &now
		if reason != "" {
			user.BanReason = &reason
		}
	}
	return nil
}

func (m *mockAdminStore) UnbanUser(ctx context.Context, userID string) error {
	if user, ok := m.users[userID]; ok {
		user.Banned = false
		user.BannedAt = nil
		user.BanReason = nil
	}
	return nil
}

func (m *mockAdminStore) SetUserRole(ctx context.Context, userID string, role string) error {
	if user, ok := m.users[userID]; ok {
		user.Role = role
	}
	return nil
}

func (m *mockAdminStore) CountUsers(ctx context.Context) (int64, error) {
	return int64(len(m.users)), nil
}

func createAdminTestAuth(t *testing.T) (*Auth, *mockAdminStore) {
	t.Helper()
	store := newMockAdminStore()

	auth, err := New(store,
		config.WithSecret("test-secret-32-bytes-long-here!!"),
		config.WithBaseURL("http://localhost:3000"),
		config.WithSessionCleanupInterval(0),
		config.WithCSRF(false), // Disable CSRF for testing
	)
	if err != nil {
		t.Fatalf("Failed to create auth: %v", err)
	}

	return auth, store
}

func createAdminSession(t *testing.T, auth *Auth, store *mockAdminStore) string {
	t.Helper()

	rawToken, _ := token.Generate()
	tokenHash := auth.tokenHasher.Hash(rawToken)

	// Create an admin user
	user := &models.User{
		ID:            "admin-user-id",
		Email:         "admin@example.com",
		EmailVerified: true,
		Name:          "Admin User",
		Role:          "admin",
		Banned:        false,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	store.users[user.ID] = user

	session := &models.Session{
		ID:        "admin-session-id",
		UserID:    user.ID,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
	}
	store.sessions[tokenHash] = session

	return rawToken
}

func createRegularUserSession(t *testing.T, auth *Auth, store *mockAdminStore) string {
	t.Helper()

	rawToken, _ := token.Generate()
	tokenHash := auth.tokenHasher.Hash(rawToken)

	// Create a regular user
	user := &models.User{
		ID:            "regular-user-id",
		Email:         "user@example.com",
		EmailVerified: true,
		Name:          "Regular User",
		Role:          "user",
		Banned:        false,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	store.users[user.ID] = user

	session := &models.Session{
		ID:        "user-session-id",
		UserID:    user.ID,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
	}
	store.sessions[tokenHash] = session

	return rawToken
}

func TestRequireAdmin_AdminUser(t *testing.T) {
	auth, store := createAdminTestAuth(t)
	defer auth.Close()

	adminToken := createAdminSession(t, auth, store)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromContext(r.Context())
		if user == nil {
			t.Error("User should be in context")
			return
		}
		if user.Role != "admin" {
			t.Errorf("User role = %s, want admin", user.Role)
		}
		w.WriteHeader(http.StatusOK)
	})

	wrapped := auth.RequireAdmin(handler)

	req := httptest.NewRequest("GET", "/admin/users", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: adminToken})
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestRequireAdmin_NonAdminUser(t *testing.T) {
	auth, store := createAdminTestAuth(t)
	defer auth.Close()

	userToken := createRegularUserSession(t, auth, store)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called for non-admin user")
	})

	wrapped := auth.RequireAdmin(handler)

	req := httptest.NewRequest("GET", "/admin/users", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: userToken})
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestRequireAdmin_NoSession(t *testing.T) {
	auth, _ := createAdminTestAuth(t)
	defer auth.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called without session")
	})

	wrapped := auth.RequireAdmin(handler)

	req := httptest.NewRequest("GET", "/admin/users", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestBannedUserCannotAuthenticate(t *testing.T) {
	auth, store := createAdminTestAuth(t)
	defer auth.Close()

	// Create a banned user with session
	rawToken, _ := token.Generate()
	tokenHash := auth.tokenHasher.Hash(rawToken)

	user := &models.User{
		ID:        "banned-user-id",
		Email:     "banned@example.com",
		Name:      "Banned User",
		Role:      "user",
		Banned:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	store.users[user.ID] = user

	session := &models.Session{
		ID:        "banned-session-id",
		UserID:    user.ID,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
	}
	store.sessions[tokenHash] = session

	handler := auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called for banned user")
	}))

	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: rawToken})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}
