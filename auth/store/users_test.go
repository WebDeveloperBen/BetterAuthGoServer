package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
)

func TestCreateUser(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)

	user := &models.User{
		ID:            uuid.New().String(),
		Email:         "test@example.com",
		Name:          "Test User",
		EmailVerified: false,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	err := tdb.Store.CreateUser(ctx, user)
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	// Verify user was created
	got, err := tdb.Store.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetUserByID() returned nil")
	}
	if got.Email != user.Email {
		t.Errorf("GetUserByID().Email = %v, want %v", got.Email, user.Email)
	}
}

func TestCreateUser_DuplicateEmail(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)

	user1 := &models.User{
		ID:        uuid.New().String(),
		Email:     "duplicate@example.com",
		Name:      "User 1",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	user2 := &models.User{
		ID:        uuid.New().String(),
		Email:     "duplicate@example.com",
		Name:      "User 2",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	err := tdb.Store.CreateUser(ctx, user1)
	if err != nil {
		t.Fatalf("CreateUser(user1) error = %v", err)
	}

	err = tdb.Store.CreateUser(ctx, user2)
	if err == nil {
		t.Error("CreateUser(user2) should fail with duplicate email")
	}
}

func TestCreateUser_WithAllFields(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)

	now := time.Now()
	image := "https://example.com/avatar.png"
	banReason := "Violated terms of service"
	user := &models.User{
		ID:            uuid.New().String(),
		Email:         "complete@example.com",
		Name:          "Complete User",
		EmailVerified: true,
		Image:         &image,
		Banned:        true,
		BannedAt:      &now,
		BanReason:     &banReason,
		Role:          "admin",
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	err := tdb.Store.CreateUser(ctx, user)
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	got, err := tdb.Store.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetUserByID() returned nil")
	}
	if got.Image == nil || *got.Image != image {
		t.Errorf("GetUserByID().Image = %v, want %v", got.Image, &image)
	}
	if !got.Banned {
		t.Error("GetUserByID().Banned should be true")
	}
	if got.BannedAt == nil {
		t.Error("GetUserByID().BannedAt should not be nil")
	}
	if got.BanReason == nil || *got.BanReason != banReason {
		t.Errorf("GetUserByID().BanReason = %v, want %v", got.BanReason, &banReason)
	}
	if got.Role != "admin" {
		t.Errorf("GetUserByID().Role = %v, want admin", got.Role)
	}
}

func TestGetUserByID(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)

	user := &models.User{
		ID:        uuid.New().String(),
		Email:     "getbyid@example.com",
		Name:      "Get By ID",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	_ = tdb.Store.CreateUser(ctx, user)

	got, err := tdb.Store.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetUserByID() returned nil")
	}
	if got.ID != user.ID {
		t.Errorf("GetUserByID().ID = %v, want %v", got.ID, user.ID)
	}
}

func TestGetUserByID_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)

	got, err := tdb.Store.GetUserByID(ctx, "nonexistent-id")
	if err != nil {
		t.Fatalf("GetUserByID() error = %v", err)
	}
	if got != nil {
		t.Error("GetUserByID() should return nil for non-existent ID")
	}
}

func TestGetUserByEmail(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)

	user := &models.User{
		ID:        uuid.New().String(),
		Email:     "findme@example.com",
		Name:      "Find Me",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	_ = tdb.Store.CreateUser(ctx, user)

	got, err := tdb.Store.GetUserByEmail(ctx, "findme@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetUserByEmail() returned nil")
	}
	if got.ID != user.ID {
		t.Errorf("GetUserByEmail().ID = %v, want %v", got.ID, user.ID)
	}
}

func TestGetUserByEmail_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)

	got, err := tdb.Store.GetUserByEmail(ctx, "nonexistent@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail() error = %v", err)
	}
	if got != nil {
		t.Error("GetUserByEmail() should return nil for non-existent email")
	}
}

func TestUpdateUser(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)

	user := &models.User{
		ID:        uuid.New().String(),
		Email:     "update@example.com",
		Name:      "Original Name",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	_ = tdb.Store.CreateUser(ctx, user)

	user.Name = "Updated Name"
	user.UpdatedAt = time.Now()

	err := tdb.Store.UpdateUser(ctx, user)
	if err != nil {
		t.Fatalf("UpdateUser() error = %v", err)
	}

	got, _ := tdb.Store.GetUserByID(ctx, user.ID)
	if got.Name != "Updated Name" {
		t.Errorf("UpdateUser() Name = %v, want %v", got.Name, "Updated Name")
	}
}

func TestUpdateUser_AllFields(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)

	user := &models.User{
		ID:        uuid.New().String(),
		Email:     "updateall@example.com",
		Name:      "Original Name",
		Role:      "user",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	_ = tdb.Store.CreateUser(ctx, user)

	// Update all optional fields
	now := time.Now()
	image := "https://example.com/new-avatar.png"
	banReason := "Spam"
	user.Name = "New Name"
	user.Image = &image
	user.Banned = true
	user.BannedAt = &now
	user.BanReason = &banReason
	user.Role = "moderator"
	user.UpdatedAt = now

	err := tdb.Store.UpdateUser(ctx, user)
	if err != nil {
		t.Fatalf("UpdateUser() error = %v", err)
	}

	got, _ := tdb.Store.GetUserByID(ctx, user.ID)
	if got.Name != "New Name" {
		t.Errorf("UpdateUser() Name = %v, want New Name", got.Name)
	}
	if got.Image == nil || *got.Image != image {
		t.Errorf("UpdateUser() Image = %v, want %v", got.Image, image)
	}
	if !got.Banned {
		t.Error("UpdateUser() Banned should be true")
	}
	if got.Role != "moderator" {
		t.Errorf("UpdateUser() Role = %v, want moderator", got.Role)
	}
}

func TestSetEmailVerified(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)

	user := &models.User{
		ID:            uuid.New().String(),
		Email:         "verify@example.com",
		Name:          "Verify Me",
		EmailVerified: false,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	_ = tdb.Store.CreateUser(ctx, user)

	err := tdb.Store.SetEmailVerified(ctx, user.ID, true)
	if err != nil {
		t.Fatalf("SetEmailVerified() error = %v", err)
	}

	got, _ := tdb.Store.GetUserByID(ctx, user.ID)
	if !got.EmailVerified {
		t.Error("SetEmailVerified() failed to set email_verified to true")
	}
}

func TestSetEmailVerified_Toggle(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)

	user := &models.User{
		ID:            uuid.New().String(),
		Email:         "toggle@example.com",
		Name:          "Toggle User",
		EmailVerified: true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	_ = tdb.Store.CreateUser(ctx, user)

	// Verify initially true
	got, _ := tdb.Store.GetUserByID(ctx, user.ID)
	if !got.EmailVerified {
		t.Fatal("Initial EmailVerified should be true")
	}

	// Set to false
	err := tdb.Store.SetEmailVerified(ctx, user.ID, false)
	if err != nil {
		t.Fatalf("SetEmailVerified(false) error = %v", err)
	}

	got, _ = tdb.Store.GetUserByID(ctx, user.ID)
	if got.EmailVerified {
		t.Error("SetEmailVerified(false) failed to set email_verified to false")
	}
}

func TestDeleteUser(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)

	user := &models.User{
		ID:        uuid.New().String(),
		Email:     "delete@example.com",
		Name:      "Delete Me",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	_ = tdb.Store.CreateUser(ctx, user)

	err := tdb.Store.DeleteUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("DeleteUser() error = %v", err)
	}

	got, _ := tdb.Store.GetUserByID(ctx, user.ID)
	if got != nil {
		t.Error("DeleteUser() failed to delete user")
	}
}

func TestDeleteUser_NonExistent(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)

	// Deleting a non-existent user should not error
	err := tdb.Store.DeleteUser(ctx, "nonexistent-id")
	if err != nil {
		t.Fatalf("DeleteUser() on non-existent user should not error, got = %v", err)
	}
}
