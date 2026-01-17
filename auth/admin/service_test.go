package admin

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
)

// mockAdminStore implements AdminStore for testing
type mockAdminStore struct {
	users map[string]*models.User
}

func newMockAdminStore() *mockAdminStore {
	return &mockAdminStore{
		users: make(map[string]*models.User),
	}
}

func (m *mockAdminStore) ListUsers(ctx context.Context, opts models.ListUsersOptions) (*models.ListUsersResult, error) {
	var users []*models.User
	for _, u := range m.users {
		// Apply filters
		if opts.Query != "" && u.Name != opts.Query && u.Email != opts.Query {
			continue
		}
		if opts.Role != "" && u.Role != opts.Role {
			continue
		}
		users = append(users, u)
	}

	total := int64(len(users))

	// Apply pagination
	start := opts.Offset
	if start > len(users) {
		start = len(users)
	}
	end := start + opts.Limit
	if end > len(users) {
		end = len(users)
	}
	users = users[start:end]

	return &models.ListUsersResult{
		Users: users,
		Total: total,
	}, nil
}

func (m *mockAdminStore) GetUser(ctx context.Context, userID string) (*models.User, error) {
	u, ok := m.users[userID]
	if !ok {
		return nil, errors.New("user not found")
	}
	return u, nil
}

func (m *mockAdminStore) UpdateUser(ctx context.Context, user *models.User) error {
	if _, ok := m.users[user.ID]; !ok {
		return errors.New("user not found")
	}
	m.users[user.ID] = user
	return nil
}

func (m *mockAdminStore) DeleteUser(ctx context.Context, userID string) error {
	if _, ok := m.users[userID]; !ok {
		return errors.New("user not found")
	}
	delete(m.users, userID)
	return nil
}

func (m *mockAdminStore) BanUser(ctx context.Context, userID string, reason *string) error {
	u, ok := m.users[userID]
	if !ok {
		return errors.New("user not found")
	}
	u.Banned = true
	u.BanReason = reason
	return nil
}

func (m *mockAdminStore) UnbanUser(ctx context.Context, userID string) error {
	u, ok := m.users[userID]
	if !ok {
		return errors.New("user not found")
	}
	u.Banned = false
	u.BanReason = nil
	return nil
}

func (m *mockAdminStore) SetUserRole(ctx context.Context, userID, role string) error {
	u, ok := m.users[userID]
	if !ok {
		return errors.New("user not found")
	}
	u.Role = role
	return nil
}

func (m *mockAdminStore) addUser(user *models.User) {
	m.users[user.ID] = user
}

func setupTestService(t *testing.T) (*Service, *mockAdminStore) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	store := newMockAdminStore()
	service := NewService(store, logger)
	return service, store
}

func TestListUsers_Empty(t *testing.T) {
	service, _ := setupTestService(t)
	ctx := context.Background()

	result, err := service.ListUsers(ctx, models.ListUsersOptions{
		Limit: 10,
	})

	if err != nil {
		t.Fatalf("ListUsers failed: %v", err)
	}

	if result.Total != 0 {
		t.Errorf("Expected total 0, got %d", result.Total)
	}

	if len(result.Users) != 0 {
		t.Errorf("Expected 0 users, got %d", len(result.Users))
	}
}

func TestListUsers_WithUsers(t *testing.T) {
	service, store := setupTestService(t)
	ctx := context.Background()

	// Create test users
	now := time.Now()
	store.addUser(&models.User{
		ID:        "user-1",
		Email:     "user1@example.com",
		Name:      "User One",
		Role:      "user",
		CreatedAt: now,
		UpdatedAt: now,
	})
	store.addUser(&models.User{
		ID:        "user-2",
		Email:     "user2@example.com",
		Name:      "User Two",
		Role:      "admin",
		CreatedAt: now,
		UpdatedAt: now,
	})

	result, err := service.ListUsers(ctx, models.ListUsersOptions{
		Limit: 10,
	})

	if err != nil {
		t.Fatalf("ListUsers failed: %v", err)
	}

	if result.Total != 2 {
		t.Errorf("Expected total 2, got %d", result.Total)
	}

	if len(result.Users) != 2 {
		t.Errorf("Expected 2 users, got %d", len(result.Users))
	}
}

func TestListUsers_WithLimit(t *testing.T) {
	service, store := setupTestService(t)
	ctx := context.Background()

	// Create multiple test users
	now := time.Now()
	for i := 1; i <= 5; i++ {
		store.addUser(&models.User{
			ID:        "user-" + string(rune(i+'0')),
			Email:     "user" + string(rune(i+'0')) + "@example.com",
			Name:      "User " + string(rune(i+'0')),
			Role:      "user",
			CreatedAt: now,
			UpdatedAt: now,
		})
	}

	result, err := service.ListUsers(ctx, models.ListUsersOptions{
		Limit: 3,
	})

	if err != nil {
		t.Fatalf("ListUsers failed: %v", err)
	}

	if result.Total != 5 {
		t.Errorf("Expected total 5, got %d", result.Total)
	}

	if len(result.Users) != 3 {
		t.Errorf("Expected 3 users (limited), got %d", len(result.Users))
	}
}

func TestGetUser_Exists(t *testing.T) {
	service, store := setupTestService(t)
	ctx := context.Background()

	now := time.Now()
	store.addUser(&models.User{
		ID:        "user-123",
		Email:     "test@example.com",
		Name:      "Test User",
		Role:      "user",
		CreatedAt: now,
		UpdatedAt: now,
	})

	retrieved, err := service.GetUser(ctx, "user-123")

	if err != nil {
		t.Fatalf("GetUser failed: %v", err)
	}

	if retrieved.ID != "user-123" {
		t.Errorf("Expected ID %q, got %q", "user-123", retrieved.ID)
	}

	if retrieved.Email != "test@example.com" {
		t.Errorf("Expected email %q, got %q", "test@example.com", retrieved.Email)
	}
}

func TestGetUser_NotFound(t *testing.T) {
	service, _ := setupTestService(t)
	ctx := context.Background()

	_, err := service.GetUser(ctx, "non-existent")

	if err != ErrUserNotFound {
		t.Errorf("Expected ErrUserNotFound, got %v", err)
	}
}

func TestUpdateUser_Success(t *testing.T) {
	service, store := setupTestService(t)
	ctx := context.Background()

	now := time.Now()
	store.addUser(&models.User{
		ID:        "user-123",
		Email:     "test@example.com",
		Name:      "Test User",
		Role:      "user",
		CreatedAt: now,
		UpdatedAt: now,
	})

	newName := "Updated Name"
	newEmail := "updated@example.com"
	newRole := "admin"

	updates := AdminUserUpdates{
		Name:  &newName,
		Email: &newEmail,
		Role:  &newRole,
	}

	updated, err := service.UpdateUser(ctx, "user-123", updates)
	if err != nil {
		t.Fatalf("UpdateUser failed: %v", err)
	}

	if updated.Name != newName {
		t.Errorf("Expected name %q, got %q", newName, updated.Name)
	}

	if updated.Email != newEmail {
		t.Errorf("Expected email %q, got %q", newEmail, updated.Email)
	}

	if updated.Role != newRole {
		t.Errorf("Expected role %q, got %q", newRole, updated.Role)
	}

	// Email change should reset verification
	if updated.EmailVerified {
		t.Error("Expected EmailVerified to be false after email change")
	}
}

func TestUpdateUser_NotFound(t *testing.T) {
	service, _ := setupTestService(t)
	ctx := context.Background()

	updates := AdminUserUpdates{
		Name: stringPtr("New Name"),
	}

	_, err := service.UpdateUser(ctx, "non-existent", updates)

	if err != ErrUserNotFound {
		t.Errorf("Expected ErrUserNotFound, got %v", err)
	}
}

func TestDeleteUser_Success(t *testing.T) {
	service, store := setupTestService(t)
	ctx := context.Background()

	now := time.Now()
	store.addUser(&models.User{
		ID:        "user-123",
		Email:     "test@example.com",
		Name:      "Test User",
		Role:      "user",
		CreatedAt: now,
		UpdatedAt: now,
	})

	// Verify user exists
	_, err := service.GetUser(ctx, "user-123")
	if err != nil {
		t.Fatalf("User should exist before deletion: %v", err)
	}

	// Delete user
	err = service.DeleteUser(ctx, "user-123")
	if err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}

	// Verify user is gone
	_, err = service.GetUser(ctx, "user-123")
	if err != ErrUserNotFound {
		t.Errorf("Expected user to be deleted, got error: %v", err)
	}
}

func TestDeleteUser_NotFound(t *testing.T) {
	service, _ := setupTestService(t)
	ctx := context.Background()

	err := service.DeleteUser(ctx, "non-existent")

	if err != ErrUserNotFound {
		t.Errorf("Expected ErrUserNotFound, got %v", err)
	}
}

func TestBanUser_Success(t *testing.T) {
	service, store := setupTestService(t)
	ctx := context.Background()

	now := time.Now()
	store.addUser(&models.User{
		ID:        "user-123",
		Email:     "test@example.com",
		Name:      "Test User",
		Role:      "user",
		Banned:    false,
		CreatedAt: now,
		UpdatedAt: now,
	})

	reason := "Violation of terms"
	err := service.BanUser(ctx, "user-123", reason)
	if err != nil {
		t.Fatalf("BanUser failed: %v", err)
	}

	// Verify user is banned
	banned, err := service.GetUser(ctx, "user-123")
	if err != nil {
		t.Fatalf("Failed to get banned user: %v", err)
	}

	if !banned.Banned {
		t.Error("User should be banned")
	}

	if banned.BanReason == nil || *banned.BanReason != reason {
		t.Errorf("Expected ban reason %q, got %v", reason, banned.BanReason)
	}
}

func TestUnbanUser_Success(t *testing.T) {
	service, store := setupTestService(t)
	ctx := context.Background()

	reason := "Violation of terms"
	now := time.Now()
	store.addUser(&models.User{
		ID:        "user-123",
		Email:     "test@example.com",
		Name:      "Test User",
		Role:      "user",
		Banned:    true,
		BanReason: &reason,
		CreatedAt: now,
		UpdatedAt: now,
	})

	err := service.UnbanUser(ctx, "user-123")
	if err != nil {
		t.Fatalf("UnbanUser failed: %v", err)
	}

	// Verify user is unbanned
	unbanned, err := service.GetUser(ctx, "user-123")
	if err != nil {
		t.Fatalf("Failed to get unbanned user: %v", err)
	}

	if unbanned.Banned {
		t.Error("User should not be banned")
	}

	if unbanned.BanReason != nil {
		t.Error("Ban reason should be cleared")
	}
}

func TestSetUserRole_Success(t *testing.T) {
	service, store := setupTestService(t)
	ctx := context.Background()

	now := time.Now()
	store.addUser(&models.User{
		ID:        "user-123",
		Email:     "test@example.com",
		Name:      "Test User",
		Role:      "user",
		CreatedAt: now,
		UpdatedAt: now,
	})

	newRole := "admin"
	err := service.SetUserRole(ctx, "user-123", newRole)
	if err != nil {
		t.Fatalf("SetUserRole failed: %v", err)
	}

	// Verify role is updated
	updated, err := service.GetUser(ctx, "user-123")
	if err != nil {
		t.Fatalf("Failed to get updated user: %v", err)
	}

	if updated.Role != newRole {
		t.Errorf("Expected role %q, got %q", newRole, updated.Role)
	}
}

func TestSetUserRole_InvalidRole(t *testing.T) {
	service, store := setupTestService(t)
	ctx := context.Background()

	now := time.Now()
	store.addUser(&models.User{
		ID:        "user-123",
		Email:     "test@example.com",
		Name:      "Test User",
		Role:      "user",
		CreatedAt: now,
		UpdatedAt: now,
	})

	err := service.SetUserRole(ctx, "user-123", "")
	if err != ErrInvalidRequest {
		t.Errorf("Expected ErrInvalidRequest for empty role, got %v", err)
	}
}

// Helper function
func stringPtr(s string) *string {
	return &s
}
