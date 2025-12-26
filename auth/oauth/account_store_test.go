package oauth

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
)

func setupTestDB(t *testing.T) *bun.DB {
	sqldb, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}

	db := bun.NewDB(sqldb, sqlitedialect.New())
	t.Cleanup(func() { _ = db.Close() })

	return db
}

func TestAccountStore_NewAccountStore(t *testing.T) {
	db := setupTestDB(t)
	store := NewAccountStore(db)

	if store == nil {
		t.Fatal("NewAccountStore returned nil")
	}
	if store.db != db {
		t.Error("AccountStore.db not set correctly")
	}
}

func TestAccountStore_CreateAccount(t *testing.T) {
	db := setupTestDB(t)
	store := NewAccountStore(db)

	// Create OAuth account
	account := &OAuthAccount{
		ID:                "account-123",
		UserID:            "user-123",
		Provider:          "google",
		ProviderAccountID: "google-user-123",
		AccessToken:       "encrypted-token",
		RefreshToken:      "encrypted-refresh",
	}

	err := store.CreateAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("CreateAccount failed: %v", err)
	}

	// Verify account was created
	found, err := store.GetAccountByProvider(context.Background(), "google", "google-user-123")
	if err != nil {
		t.Fatalf("GetAccountByProvider failed: %v", err)
	}
	if found == nil {
		t.Fatal("Account not found after creation")
	}
	if found.UserID != "user-123" {
		t.Errorf("Account UserID = %s, want user-123", found.UserID)
	}
	if found.Provider != "google" {
		t.Errorf("Account Provider = %s, want google", found.Provider)
	}
	if found.AccessToken != "encrypted-token" {
		t.Errorf("AccessToken = %s, want encrypted-token", found.AccessToken)
	}
}

func TestAccountStore_GetAccountByProvider_NotFound(t *testing.T) {
	db := setupTestDB(t)
	store := NewAccountStore(db)

	// Test account not found
	account, err := store.GetAccountByProvider(context.Background(), "google", "nonexistent")
	if err == nil {
		t.Error("Expected error for non-existent account, got nil")
	}
	if account != nil {
		t.Error("Expected nil account for non-existent provider/account")
	}
}

func TestAccountStore_UpdateAccount(t *testing.T) {
	db := setupTestDB(t)
	store := NewAccountStore(db)

	// Create account first
	account := &OAuthAccount{
		ID:                "update-account",
		UserID:            "user-456",
		Provider:          "github",
		ProviderAccountID: "github-user-123",
		AccessToken:       "old-token",
	}
	err := store.CreateAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("CreateAccount failed: %v", err)
	}

	// Update account
	account.AccessToken = "new-encrypted-token"
	account.RefreshToken = "new-encrypted-refresh"
	expiresAt := time.Now().Add(time.Hour)
	account.AccessTokenExpiresAt = &expiresAt

	err = store.UpdateAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("UpdateAccount failed: %v", err)
	}

	// Verify update
	updated, err := store.GetAccountByProvider(context.Background(), "github", "github-user-123")
	if err != nil {
		t.Fatalf("GetAccountByProvider after update failed: %v", err)
	}
	if updated.AccessToken != "new-encrypted-token" {
		t.Errorf("AccessToken = %s, want new-encrypted-token", updated.AccessToken)
	}
	if updated.RefreshToken != "new-encrypted-refresh" {
		t.Errorf("RefreshToken = %s, want new-encrypted-refresh", updated.RefreshToken)
	}
	if updated.AccessTokenExpiresAt == nil || !updated.AccessTokenExpiresAt.Equal(expiresAt) {
		t.Errorf("AccessTokenExpiresAt not updated correctly")
	}
}
