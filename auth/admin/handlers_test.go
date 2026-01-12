package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/admin/access"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// mockService implements AdminOperations for testing
type mockService struct {
	users  map[string]*models.User
	nextID int
}

func newMockService() *mockService {
	return &mockService{
		users:  make(map[string]*models.User),
		nextID: 1,
	}
}

func (m *mockService) ListUsers(ctx context.Context, opts models.ListUsersOptions) (*models.ListUsersResult, error) {
	users := make([]*models.User, 0, len(m.users))
	for _, user := range m.users {
		users = append(users, user)
	}

	// Apply limit
	if opts.Limit > 0 && len(users) > opts.Limit {
		users = users[:opts.Limit]
	}

	return &models.ListUsersResult{
		Users: users,
		Total: int64(len(m.users)),
	}, nil
}

func (m *mockService) GetUser(ctx context.Context, userID string) (*models.User, error) {
	if user, ok := m.users[userID]; ok {
		return user, nil
	}
	return nil, ErrUserNotFound
}

func (m *mockService) UpdateUser(ctx context.Context, userID string, updates AdminUserUpdates) (*models.User, error) {
	user, err := m.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	if updates.Name != nil {
		user.Name = *updates.Name
	}
	if updates.Email != nil {
		user.Email = *updates.Email
	}
	if updates.Role != nil {
		user.Role = *updates.Role
	}

	return user, nil
}

func (m *mockService) DeleteUser(ctx context.Context, userID string) error {
	if _, ok := m.users[userID]; !ok {
		return ErrUserNotFound
	}
	delete(m.users, userID)
	return nil
}

func (m *mockService) BanUser(ctx context.Context, userID, reason string) error {
	user, err := m.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	user.Banned = true
	user.BanReason = &reason
	return nil
}

func (m *mockService) UnbanUser(ctx context.Context, userID string) error {
	user, err := m.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	user.Banned = false
	user.BanReason = nil
	return nil
}

func (m *mockService) SetUserRole(ctx context.Context, userID, role string) error {
	user, err := m.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	user.Role = role
	return nil
}

func TestParseUserPath(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		wantUserID string
		wantAction string
	}{
		{"base path", "/admin/users", "", ""},
		{"base path with trailing slash", "/admin/users/", "", ""},
		{"with user id", "/admin/users/123", "123", ""},
		{"with ban action", "/admin/users/123/ban", "123", "ban"},
		{"with role action", "/admin/users/123/role", "123", "role"},
		{"with uuid-style id", "/admin/users/abc-123-def", "abc-123-def", ""},
		{"with extra path segments", "/admin/users/123/invalid/action", "123", "invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUserID, gotAction := parseUserPath(tt.path)
			if gotUserID != tt.wantUserID {
				t.Errorf("parseUserPath(%q) userID = %q, want %q", tt.path, gotUserID, tt.wantUserID)
			}
			if gotAction != tt.wantAction {
				t.Errorf("parseUserPath(%q) action = %q, want %q", tt.path, gotAction, tt.wantAction)
			}
		})
	}
}

func TestHasPermission_InvalidAccessControl(t *testing.T) {
	service := newMockService()

	// Create user
	user := &models.User{
		ID:   "user-123",
		Role: "user",
	}
	service.users[user.ID] = user

	// Create handlers with nil config (access control not configured)
	config := &Config{}
	handlers := newHandlers(service, &mockAuth{}, &mockSessionManager{}, &mockHandlersUserProvider{}, config, slog.Default())

	// Send valid JSON request
	reqBody := hasPermissionRequest{
		UserID: stringPtr("user-123"),
		Permissions: map[string][]string{
			"user": {"list"},
		},
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/admin/permissions/has-permission", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.hasPermission(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

func TestHasPermission_UserNotFound(t *testing.T) {
	service := newMockService()

	// Create access control
	ac, _ := access.CreateDefaultAccessControl()
	config := &Config{AccessControl: ac}
	handlers := newHandlers(service, &mockAuth{}, &mockSessionManager{}, &mockHandlersUserProvider{}, config, slog.Default())

	// Create request for non-existent user
	reqBody := hasPermissionRequest{
		UserID: stringPtr("non-existent"),
		Permissions: map[string][]string{
			"user": {"list"},
		},
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/admin/permissions/has-permission", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.hasPermission(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

func TestHasPermission_ValidUser(t *testing.T) {
	service := newMockService()

	// Create user with admin role
	user := &models.User{
		ID:   "admin-123",
		Role: "admin",
	}
	service.users[user.ID] = user

	// Create access control
	ac, _ := access.CreateDefaultAccessControl()
	config := &Config{AccessControl: ac}
	handlers := newHandlers(service, &mockAuth{}, &mockSessionManager{}, &mockHandlersUserProvider{}, config, slog.Default())

	// Create request
	reqBody := hasPermissionRequest{
		UserID: stringPtr("admin-123"),
		Permissions: map[string][]string{
			"user": {"list"}, // Admin role has this permission
		},
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/admin/permissions/has-permission", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.hasPermission(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response permissionResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if !response.HasPermission {
		t.Error("Expected user to have permission")
	}
}

func TestHasPermission_InvalidRole(t *testing.T) {
	service := newMockService()

	// Create access control
	ac, _ := access.CreateDefaultAccessControl()
	config := &Config{AccessControl: ac}
	handlers := newHandlers(service, &mockAuth{}, &mockSessionManager{}, &mockHandlersUserProvider{}, config, slog.Default())

	// Create request with invalid role
	reqBody := hasPermissionRequest{
		Role: stringPtr("invalid-role"),
		Permissions: map[string][]string{
			"user": {"list"},
		},
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/admin/permissions/has-permission", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.hasPermission(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

func TestHasPermission_NoUserOrRole(t *testing.T) {
	service := newMockService()

	// Create access control
	ac, _ := access.CreateDefaultAccessControl()
	config := &Config{AccessControl: ac}
	handlers := newHandlers(service, &mockAuth{}, &mockSessionManager{}, &mockHandlersUserProvider{}, config, slog.Default())

	// Create request with neither userId nor role
	reqBody := hasPermissionRequest{
		Permissions: map[string][]string{
			"user": {"list"},
		},
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/admin/permissions/has-permission", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.hasPermission(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestCheckRolePermission_InvalidAccessControl(t *testing.T) {
	service := newMockService()

	// Create handlers with nil config
	config := &Config{}
	handlers := newHandlers(service, &mockAuth{}, &mockSessionManager{}, &mockHandlersUserProvider{}, config, slog.Default())

	// Send valid JSON request
	reqBody := checkRolePermissionRequest{
		Role: "admin",
		Permissions: map[string][]string{
			"user": {"list"},
		},
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/admin/permissions/check-role", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.checkRolePermission(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

func TestCheckRolePermission_InvalidRole(t *testing.T) {
	service := newMockService()

	// Create access control
	ac, _ := access.CreateDefaultAccessControl()
	config := &Config{AccessControl: ac}
	handlers := newHandlers(service, &mockAuth{}, &mockSessionManager{}, &mockHandlersUserProvider{}, config, slog.Default())

	// Create request with invalid role
	reqBody := checkRolePermissionRequest{
		Role: "invalid-role",
		Permissions: map[string][]string{
			"user": {"list"},
		},
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/admin/permissions/check-role", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.checkRolePermission(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

func TestCheckRolePermission_ValidRole(t *testing.T) {
	service := newMockService()

	// Create access control
	ac, _ := access.CreateDefaultAccessControl()
	config := &Config{AccessControl: ac}
	handlers := newHandlers(service, &mockAuth{}, &mockSessionManager{}, &mockHandlersUserProvider{}, config, slog.Default())

	// Create request for admin role
	reqBody := checkRolePermissionRequest{
		Role: "admin",
		Permissions: map[string][]string{
			"user": {"list"}, // Admin role should have this
		},
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/admin/permissions/check-role", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.checkRolePermission(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response permissionResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if !response.HasPermission {
		t.Error("Expected admin role to have user:list permission")
	}
}

// mockAuth implements plugin.AuthCore for testing
type mockAuth struct{}

func (m *mockAuth) BaseURL() string {
	return "http://localhost:8080"
}

func (m *mockAuth) Secret() string {
	return "test-secret"
}

// mockSessionManager implements plugin.SessionManager for testing
type mockSessionManager struct {
	session *plugin.Session
}

func (m *mockSessionManager) GetFromRequest(r *http.Request) *plugin.Session {
	return m.session
}

func (m *mockSessionManager) Create(ctx context.Context, userID string, r *http.Request) (*plugin.Session, error) {
	return &plugin.Session{
		ID:        "session-123",
		UserID:    userID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		RawToken:  "test-token",
	}, nil
}

func (m *mockSessionManager) CreateWithImpersonation(ctx context.Context, targetUserID, impersonatedBy string, r *http.Request, duration time.Duration) (*plugin.Session, error) {
	return &plugin.Session{
		ID:             "imp-session-123",
		UserID:         targetUserID,
		ImpersonatedBy: &impersonatedBy,
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(duration),
		RawToken:       "imp-test-token",
	}, nil
}

func (m *mockSessionManager) Get(ctx context.Context, sessionID string) (*plugin.Session, error) {
	if m.session != nil && m.session.ID == sessionID {
		return m.session, nil
	}
	return nil, nil
}

func (m *mockSessionManager) Delete(ctx context.Context, sessionID string) error {
	return nil
}

func (m *mockSessionManager) WriteAuthResponse(ctx context.Context, w http.ResponseWriter, session *plugin.Session, user *plugin.User) error {
	return nil
}

func (m *mockSessionManager) ClearAuthResponse(w http.ResponseWriter) {}

func (m *mockSessionManager) GetSessionToken(r *http.Request) string {
	return "test-token"
}

func (m *mockSessionManager) SetSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
}

// mockHandlersUserProvider implements UserProvider for handler tests
type mockHandlersUserProvider struct {
	user  *plugin.User
	users map[string]*plugin.User
}

func (m *mockHandlersUserProvider) GetUserFromRequest(r *http.Request) (*plugin.User, error) {
	return m.user, nil
}

func (m *mockHandlersUserProvider) GetPluginUser(ctx context.Context, userID string) (*plugin.User, error) {
	if m.users != nil {
		if user, ok := m.users[userID]; ok {
			return user, nil
		}
	}
	if m.user != nil && m.user.ID == userID {
		return m.user, nil
	}
	return nil, ErrUserNotFound
}
