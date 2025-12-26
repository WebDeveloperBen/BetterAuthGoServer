package admin

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/admin/access"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// mockUserProvider implements UserProvider for testing
type mockUserProvider struct {
	user *plugin.User
	err  error
}

func (m *mockUserProvider) GetUserFromRequest(r *http.Request) (*plugin.User, error) {
	return m.user, m.err
}

func TestRequireAdmin_AdminUser(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	
	// Create access control
	ac, err := access.CreateDefaultAccessControl()
	if err != nil {
		t.Fatalf("Failed to create access control: %v", err)
	}
	
	// Create admin user
	adminUser := &plugin.User{
		ID:   "admin-123",
		Role: "admin",
	}
	
	provider := &mockUserProvider{user: adminUser}
	middleware := RequireAdmin(provider, logger, ac)
	
	req := httptest.NewRequest("GET", "/admin/users", nil)
	w := httptest.NewRecorder()
	
	called := false
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	
	handler.ServeHTTP(w, req)
	
	if !called {
		t.Error("Handler should have been called for admin user")
	}
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestRequireAdmin_NonAdminUser(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	
	// Create access control
	ac, err := access.CreateDefaultAccessControl()
	if err != nil {
		t.Fatalf("Failed to create access control: %v", err)
	}
	
	// Create regular user
	regularUser := &plugin.User{
		ID:   "user-123",
		Role: "user",
	}
	
	provider := &mockUserProvider{user: regularUser}
	middleware := RequireAdmin(provider, logger, ac)
	
	req := httptest.NewRequest("GET", "/admin/users", nil)
	w := httptest.NewRecorder()
	
	called := false
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	
	handler.ServeHTTP(w, req)
	
	if called {
		t.Error("Handler should not have been called for non-admin user")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", w.Code)
	}
}

func TestRequireAdmin_NoSession(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	
	// Create access control
	ac, err := access.CreateDefaultAccessControl()
	if err != nil {
		t.Fatalf("Failed to create access control: %v", err)
	}
	
	provider := &mockUserProvider{err: http.ErrNoCookie}
	middleware := RequireAdmin(provider, logger, ac)
	
	req := httptest.NewRequest("GET", "/admin/users", nil)
	w := httptest.NewRecorder()
	
	called := false
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	
	handler.ServeHTTP(w, req)
	
	if called {
		t.Error("Handler should not have been called without authentication")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestRequirePermissions_SpecificPermission(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	
	// Create access control with custom permissions
	statement := access.Statement{
		"project": {"create", "read"},
	}
	ac := access.NewAccessControl(statement)
	
	// Create role with create permission
	role, _ := ac.NewRole(access.Permissions{
		"project": {"create"},
	})
	ac.RegisterRole("creator", role)
	
	user := &plugin.User{
		ID:   "user-123",
		Role: "creator",
	}
	
	provider := &mockUserProvider{user: user}
	middleware := RequirePermissions(provider, logger, ac, map[string][]string{
		"project": {"create"},
	})
	
	req := httptest.NewRequest("POST", "/api/projects", nil)
	w := httptest.NewRecorder()
	
	called := false
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusCreated)
	}))
	
	handler.ServeHTTP(w, req)
	
	if !called {
		t.Error("Handler should have been called for user with required permission")
	}
	if w.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d", w.Code)
	}
}

func TestRequirePermissions_InsufficientPermission(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	
	// Create access control with custom permissions
	statement := access.Statement{
		"project": {"create", "read", "delete"},
	}
	ac := access.NewAccessControl(statement)
	
	// Create role with only read permission
	role, _ := ac.NewRole(access.Permissions{
		"project": {"read"},
	})
	ac.RegisterRole("reader", role)
	
	user := &plugin.User{
		ID:   "user-123",
		Role: "reader",
	}
	
	provider := &mockUserProvider{user: user}
	middleware := RequirePermissions(provider, logger, ac, map[string][]string{
		"project": {"delete"},
	})
	
	req := httptest.NewRequest("DELETE", "/api/projects/123", nil)
	w := httptest.NewRecorder()
	
	called := false
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	
	handler.ServeHTTP(w, req)
	
	if called {
		t.Error("Handler should not have been called for user without required permission")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", w.Code)
	}
}

func TestRequirePermissions_NoAccessControl(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	
	// Test with nil access control (falls back to role-based)
	user := &plugin.User{
		ID:   "admin-123",
		Role: "admin",
	}
	
	provider := &mockUserProvider{user: user}
	middleware := RequirePermissions(provider, logger, nil, map[string][]string{
		"project": {"create"},
	})
	
	req := httptest.NewRequest("POST", "/api/projects", nil)
	w := httptest.NewRecorder()
	
	called := false
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusCreated)
	}))
	
	handler.ServeHTTP(w, req)
	
	if !called {
		t.Error("Handler should have been called for admin user when no access control")
	}
	if w.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d", w.Code)
	}
}
