package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
)

func TestCreateAccount_Email(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	passwordHash := "$argon2id$v=19$m=65536,t=3,p=4$..."
	account := &models.Account{
		ID:           uuid.New().String(),
		UserID:       user.ID,
		Provider:     models.ProviderEmail,
		PasswordHash: &passwordHash,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	err := tdb.Store.CreateAccount(ctx, account)
	if err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}

	got, err := tdb.Store.GetAccountByID(ctx, account.ID)
	if err != nil {
		t.Fatalf("GetAccountByID() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetAccountByID() returned nil")
	}
	if got.Provider != models.ProviderEmail {
		t.Errorf("GetAccountByID().Provider = %v, want %v", got.Provider, models.ProviderEmail)
	}
}

func TestCreateAccount_OAuth(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	providerID := "google-123456"
	account := &models.Account{
		ID:                uuid.New().String(),
		UserID:            user.ID,
		Provider:          models.ProviderGoogle,
		ProviderAccountID: &providerID,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	err := tdb.Store.CreateAccount(ctx, account)
	if err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}

	got, err := tdb.Store.GetAccountByProvider(ctx, models.ProviderGoogle, providerID)
	if err != nil {
		t.Fatalf("GetAccountByProvider() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetAccountByProvider() returned nil")
	}
}

func TestGetAccountByID(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	account := &models.Account{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Provider:  models.ProviderEmail,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	_ = tdb.Store.CreateAccount(ctx, account)

	got, err := tdb.Store.GetAccountByID(ctx, account.ID)
	if err != nil {
		t.Fatalf("GetAccountByID() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetAccountByID() returned nil")
	}
	if got.ID != account.ID {
		t.Errorf("GetAccountByID().ID = %v, want %v", got.ID, account.ID)
	}
}

func TestGetAccountByID_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)

	got, err := tdb.Store.GetAccountByID(ctx, "nonexistent-id")
	if err != nil {
		t.Fatalf("GetAccountByID() error = %v", err)
	}
	if got != nil {
		t.Error("GetAccountByID() should return nil for non-existent ID")
	}
}

func TestGetAccountByUserIDAndProvider(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	passwordHash := "hash"
	account := &models.Account{
		ID:           uuid.New().String(),
		UserID:       user.ID,
		Provider:     models.ProviderEmail,
		PasswordHash: &passwordHash,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	_ = tdb.Store.CreateAccount(ctx, account)

	got, err := tdb.Store.GetAccountByUserIDAndProvider(ctx, user.ID, models.ProviderEmail)
	if err != nil {
		t.Fatalf("GetAccountByUserIDAndProvider() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetAccountByUserIDAndProvider() returned nil")
	}
	if got.ID != account.ID {
		t.Errorf("GetAccountByUserIDAndProvider().ID = %v, want %v", got.ID, account.ID)
	}
}

func TestGetAccountByUserIDAndProvider_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	got, err := tdb.Store.GetAccountByUserIDAndProvider(ctx, user.ID, models.ProviderGoogle)
	if err != nil {
		t.Fatalf("GetAccountByUserIDAndProvider() error = %v", err)
	}
	if got != nil {
		t.Error("GetAccountByUserIDAndProvider() should return nil for non-existent provider")
	}
}

func TestGetAccountByProvider(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	providerID := "github-789"
	account := &models.Account{
		ID:                uuid.New().String(),
		UserID:            user.ID,
		Provider:          models.ProviderGitHub,
		ProviderAccountID: &providerID,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}
	_ = tdb.Store.CreateAccount(ctx, account)

	got, err := tdb.Store.GetAccountByProvider(ctx, models.ProviderGitHub, providerID)
	if err != nil {
		t.Fatalf("GetAccountByProvider() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetAccountByProvider() returned nil")
	}
	if got.ID != account.ID {
		t.Errorf("GetAccountByProvider().ID = %v, want %v", got.ID, account.ID)
	}
}

func TestGetAccountByProvider_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)

	got, err := tdb.Store.GetAccountByProvider(ctx, models.ProviderGoogle, "nonexistent-provider-id")
	if err != nil {
		t.Fatalf("GetAccountByProvider() error = %v", err)
	}
	if got != nil {
		t.Error("GetAccountByProvider() should return nil for non-existent provider account ID")
	}
}

func TestListAccountsByUserID(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	// Create multiple accounts
	for _, provider := range []models.ProviderType{models.ProviderEmail, models.ProviderGoogle} {
		account := &models.Account{
			ID:        uuid.New().String(),
			UserID:    user.ID,
			Provider:  provider,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		_ = tdb.Store.CreateAccount(ctx, account)
	}

	accounts, err := tdb.Store.ListAccountsByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListAccountsByUserID() error = %v", err)
	}
	if len(accounts) != 2 {
		t.Errorf("ListAccountsByUserID() returned %d accounts, want 2", len(accounts))
	}
}

func TestListAccountsByUserID_Empty(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	accounts, err := tdb.Store.ListAccountsByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListAccountsByUserID() error = %v", err)
	}
	if len(accounts) != 0 {
		t.Errorf("ListAccountsByUserID() returned %d accounts, want 0", len(accounts))
	}
}

func TestListAccountsByUserID_MultipleProviders(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	providers := []models.ProviderType{
		models.ProviderEmail,
		models.ProviderGoogle,
		models.ProviderGitHub,
		models.ProviderDiscord,
	}

	for _, provider := range providers {
		account := &models.Account{
			ID:        uuid.New().String(),
			UserID:    user.ID,
			Provider:  provider,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		_ = tdb.Store.CreateAccount(ctx, account)
	}

	accounts, err := tdb.Store.ListAccountsByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListAccountsByUserID() error = %v", err)
	}
	if len(accounts) != 4 {
		t.Errorf("ListAccountsByUserID() returned %d accounts, want 4", len(accounts))
	}

	// Verify all providers are present
	providerMap := make(map[models.ProviderType]bool)
	for _, acc := range accounts {
		providerMap[acc.Provider] = true
	}
	for _, provider := range providers {
		if !providerMap[provider] {
			t.Errorf("ListAccountsByUserID() missing provider %v", provider)
		}
	}
}

func TestUpdateAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	providerID := "google-123"
	account := &models.Account{
		ID:                uuid.New().String(),
		UserID:            user.ID,
		Provider:          models.ProviderGoogle,
		ProviderAccountID: &providerID,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}
	_ = tdb.Store.CreateAccount(ctx, account)

	// Update the provider account ID
	newProviderID := "google-456"
	account.ProviderAccountID = &newProviderID

	err := tdb.Store.UpdateAccount(ctx, account)
	if err != nil {
		t.Fatalf("UpdateAccount() error = %v", err)
	}

	got, _ := tdb.Store.GetAccountByID(ctx, account.ID)
	if got.ProviderAccountID == nil || *got.ProviderAccountID != newProviderID {
		t.Error("UpdateAccount() failed to update provider_account_id")
	}
}

func TestUpdateAccount_PasswordHash(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	oldHash := "old-password-hash"
	account := &models.Account{
		ID:           uuid.New().String(),
		UserID:       user.ID,
		Provider:     models.ProviderEmail,
		PasswordHash: &oldHash,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	_ = tdb.Store.CreateAccount(ctx, account)

	// Update password hash
	newHash := "new-password-hash"
	account.PasswordHash = &newHash

	err := tdb.Store.UpdateAccount(ctx, account)
	if err != nil {
		t.Fatalf("UpdateAccount() error = %v", err)
	}

	got, _ := tdb.Store.GetAccountByID(ctx, account.ID)
	if got.PasswordHash == nil || *got.PasswordHash != newHash {
		t.Error("UpdateAccount() failed to update password_hash")
	}
}

func TestDeleteAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	account := &models.Account{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Provider:  models.ProviderEmail,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	_ = tdb.Store.CreateAccount(ctx, account)

	err := tdb.Store.DeleteAccount(ctx, account.ID)
	if err != nil {
		t.Fatalf("DeleteAccount() error = %v", err)
	}

	got, _ := tdb.Store.GetAccountByID(ctx, account.ID)
	if got != nil {
		t.Error("DeleteAccount() failed to delete account")
	}
}

func TestDeleteAccount_NonExistent(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)

	err := tdb.Store.DeleteAccount(ctx, "nonexistent-id")
	if err != nil {
		t.Fatalf("DeleteAccount() on non-existent account should not error, got = %v", err)
	}
}

func TestDeleteAccountsByUserID(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	// Create multiple accounts
	for range 3 {
		account := &models.Account{
			ID:        uuid.New().String(),
			UserID:    user.ID,
			Provider:  models.ProviderEmail,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		_ = tdb.Store.CreateAccount(ctx, account)
	}

	err := tdb.Store.DeleteAccountsByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("DeleteAccountsByUserID() error = %v", err)
	}

	accounts, _ := tdb.Store.ListAccountsByUserID(ctx, user.ID)
	if len(accounts) != 0 {
		t.Errorf("DeleteAccountsByUserID() left %d accounts", len(accounts))
	}
}

func TestDeleteAccountsByUserID_DoesNotAffectOtherUsers(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user1 := createTestUser(t, tdb)
	user2 := createTestUser(t, tdb)

	// Create accounts for both users
	for _, user := range []*models.User{user1, user2} {
		account := &models.Account{
			ID:        uuid.New().String(),
			UserID:    user.ID,
			Provider:  models.ProviderEmail,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		_ = tdb.Store.CreateAccount(ctx, account)
	}

	// Delete only user1's accounts
	_ = tdb.Store.DeleteAccountsByUserID(ctx, user1.ID)

	// user1 should have no accounts
	accounts1, _ := tdb.Store.ListAccountsByUserID(ctx, user1.ID)
	if len(accounts1) != 0 {
		t.Errorf("User1 should have 0 accounts, got %d", len(accounts1))
	}

	// user2 should still have their account
	accounts2, _ := tdb.Store.ListAccountsByUserID(ctx, user2.ID)
	if len(accounts2) != 1 {
		t.Errorf("User2 should have 1 account, got %d", len(accounts2))
	}
}
