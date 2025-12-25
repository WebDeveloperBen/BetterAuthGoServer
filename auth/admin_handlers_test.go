package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

func (m *mockAdminStore) ListUsers(ctx context.Context, opts ListUsersOptions) (*ListUsersResult, error) {
	var users []*User
	for _, u := range m.users {
		users = append(users, u)
	}
	return &ListUsersResult{
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
		WithSecret("test-secret-32-bytes-long-here!!"),
		WithBaseURL("http://localhost:3000"),
		WithSessionCleanupInterval(0),
		WithCSRF(false), // Disable CSRF for testing
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
	user := &User{
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

	session := &Session{
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
	user := &User{
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

	session := &Session{
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

func TestHandleAdminListUsers(t *testing.T) {
	auth, store := createAdminTestAuth(t)
	defer auth.Close()

	adminToken := createAdminSession(t, auth, store)

	// Add some test users
	store.users["user-1"] = &User{
		ID:        "user-1",
		Email:     "user1@example.com",
		Name:      "User 1",
		Role:      "user",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	store.users["user-2"] = &User{
		ID:        "user-2",
		Email:     "user2@example.com",
		Name:      "User 2",
		Role:      "user",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	handler := auth.Handler()

	req := httptest.NewRequest("GET", "/admin/users", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: adminToken})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}

	var response AdminListUsersResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Should have at least 3 users (admin + 2 test users)
	if len(response.Users) < 3 {
		t.Errorf("Expected at least 3 users, got %d", len(response.Users))
	}
}

func TestHandleAdminBanUser(t *testing.T) {
	auth, store := createAdminTestAuth(t)
	defer auth.Close()

	adminToken := createAdminSession(t, auth, store)

	// Create a user to ban
	targetUser := &User{
		ID:        "target-user-id",
		Email:     "target@example.com",
		Name:      "Target User",
		Role:      "user",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	store.users[targetUser.ID] = targetUser

	handler := auth.Handler()

	body := `{"reason": "Test ban reason"}`
	req := httptest.NewRequest("POST", "/admin/users/target-user-id/ban", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "session", Value: adminToken})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("Status = %d, want %d. Body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	// Verify user is banned
	if !store.users[targetUser.ID].Banned {
		t.Error("User should be banned")
	}
}

func TestHandleAdminUnbanUser(t *testing.T) {
	auth, store := createAdminTestAuth(t)
	defer auth.Close()

	adminToken := createAdminSession(t, auth, store)

	// Create a banned user
	reason := "Previous ban"
	now := time.Now()
	targetUser := &User{
		ID:        "target-user-id",
		Email:     "target@example.com",
		Name:      "Target User",
		Role:      "user",
		Banned:    true,
		BannedAt:  &now,
		BanReason: &reason,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	store.users[targetUser.ID] = targetUser

	handler := auth.Handler()

	req := httptest.NewRequest("POST", "/admin/users/target-user-id/unban", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: adminToken})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("Status = %d, want %d. Body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	// Verify user is unbanned
	if store.users[targetUser.ID].Banned {
		t.Error("User should be unbanned")
	}
}

func TestHandleAdminSetRole(t *testing.T) {
	auth, store := createAdminTestAuth(t)
	defer auth.Close()

	adminToken := createAdminSession(t, auth, store)

	// Create a user
	targetUser := &User{
		ID:        "target-user-id",
		Email:     "target@example.com",
		Name:      "Target User",
		Role:      "user",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	store.users[targetUser.ID] = targetUser

	handler := auth.Handler()

	body := `{"role": "moderator"}`
	req := httptest.NewRequest("POST", "/admin/users/target-user-id/role", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "session", Value: adminToken})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("Status = %d, want %d. Body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	// Verify role is updated
	if store.users[targetUser.ID].Role != "moderator" {
		t.Errorf("User role = %s, want moderator", store.users[targetUser.ID].Role)
	}
}

func TestHandleGetProfile(t *testing.T) {
	auth, store := createAdminTestAuth(t)
	defer auth.Close()

	userToken := createRegularUserSession(t, auth, store)

	handler := auth.Handler()

	req := httptest.NewRequest("GET", "/profile", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: userToken})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d. Body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var response UserResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response.Email != "user@example.com" {
		t.Errorf("Email = %s, want user@example.com", response.Email)
	}
}

func TestHandleUpdateProfile(t *testing.T) {
	auth, store := createAdminTestAuth(t)
	defer auth.Close()

	userToken := createRegularUserSession(t, auth, store)

	handler := auth.Handler()

	body := `{"name": "Updated Name"}`
	req := httptest.NewRequest("PATCH", "/profile", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "session", Value: userToken})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d. Body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var response UserResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response.Name != "Updated Name" {
		t.Errorf("Name = %s, want Updated Name", response.Name)
	}
}

func TestBannedUserCannotAuthenticate(t *testing.T) {
	auth, store := createAdminTestAuth(t)
	defer auth.Close()

	// Create a banned user with session
	rawToken, _ := token.Generate()
	tokenHash := auth.tokenHasher.Hash(rawToken)

	user := &User{
		ID:        "banned-user-id",
		Email:     "banned@example.com",
		Name:      "Banned User",
		Role:      "user",
		Banned:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	store.users[user.ID] = user

	session := &Session{
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
