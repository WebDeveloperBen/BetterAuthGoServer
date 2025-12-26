package webauthn

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
	t.Helper()
	sqldb, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	db := bun.NewDB(sqldb, sqlitedialect.New())
	t.Cleanup(func() { db.Close() })
	return db
}

func TestNewStore(t *testing.T) {
	db := setupTestDB(t)
	store := NewStore(db)

	if store == nil {
		t.Fatal("expected store to not be nil")
	}
	if store.db != db {
		t.Error("expected store.db to match provided db")
	}
}

func TestStore_CredentialOperations(t *testing.T) {
	db := setupTestDB(t)
	store := NewStore(db)
	ctx := context.Background()

	// Test create
	credential := &WebAuthnCredential{
		ID:           "cred-1",
		UserID:       "user-1",
		CredentialID: []byte("credential-id-bytes"),
		PublicKey:    []byte("public-key-bytes"),
		SignCount:    0,
		Transports:   []string{"usb", "nfc"},
		CreatedAt:    time.Now(),
	}

	if err := store.CreateCredential(ctx, credential); err != nil {
		t.Fatalf("CreateCredential failed: %v", err)
	}

	// Test get by credential ID
	found, err := store.GetCredentialByID(ctx, []byte("credential-id-bytes"))
	if err != nil {
		t.Fatalf("GetCredentialByID failed: %v", err)
	}
	if found == nil {
		t.Fatal("expected to find credential")
	}
	if found.ID != "cred-1" {
		t.Errorf("expected ID 'cred-1', got %q", found.ID)
	}
	if found.UserID != "user-1" {
		t.Errorf("expected UserID 'user-1', got %q", found.UserID)
	}

	// Test get non-existent
	notFound, err := store.GetCredentialByID(ctx, []byte("non-existent"))
	if err != nil {
		t.Fatalf("GetCredentialByID for non-existent failed: %v", err)
	}
	if notFound != nil {
		t.Error("expected nil for non-existent credential")
	}

	// Test list by user
	credentials, err := store.ListCredentialsByUser(ctx, "user-1")
	if err != nil {
		t.Fatalf("ListCredentialsByUser failed: %v", err)
	}
	if len(credentials) != 1 {
		t.Errorf("expected 1 credential, got %d", len(credentials))
	}

	// Test list by non-existent user
	emptyList, err := store.ListCredentialsByUser(ctx, "non-existent-user")
	if err != nil {
		t.Fatalf("ListCredentialsByUser for non-existent user failed: %v", err)
	}
	if len(emptyList) != 0 {
		t.Errorf("expected 0 credentials, got %d", len(emptyList))
	}

	// Test update sign count
	newTime := time.Now()
	if err := store.UpdateCredentialSignCount(ctx, "cred-1", 5, newTime); err != nil {
		t.Fatalf("UpdateCredentialSignCount failed: %v", err)
	}

	updated, err := store.GetCredentialByID(ctx, []byte("credential-id-bytes"))
	if err != nil {
		t.Fatalf("GetCredentialByID after update failed: %v", err)
	}
	if updated.SignCount != 5 {
		t.Errorf("expected SignCount 5, got %d", updated.SignCount)
	}

	// Test delete
	if err := store.DeleteCredential(ctx, "cred-1"); err != nil {
		t.Fatalf("DeleteCredential failed: %v", err)
	}

	deleted, err := store.GetCredentialByID(ctx, []byte("credential-id-bytes"))
	if err != nil {
		t.Fatalf("GetCredentialByID after delete failed: %v", err)
	}
	if deleted != nil {
		t.Error("expected nil after delete")
	}
}

func TestStore_SessionOperations(t *testing.T) {
	db := setupTestDB(t)
	store := NewStore(db)
	ctx := context.Background()
	userID := "user-1"

	// Test create session
	session := &WebAuthnSession{
		ID:        "session-1",
		UserID:    &userID,
		Type:      "register",
		Data:      []byte("encrypted-session-data"),
		ExpiresAt: time.Now().Add(5 * time.Minute),
		CreatedAt: time.Now(),
	}

	if err := store.CreateSession(ctx, session); err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Test get session
	found, err := store.GetSession(ctx, "session-1")
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if found == nil {
		t.Fatal("expected to find session")
	}
	if found.Type != "register" {
		t.Errorf("expected Type 'register', got %q", found.Type)
	}
	if found.UserID == nil || *found.UserID != "user-1" {
		t.Error("expected UserID 'user-1'")
	}

	// Test get non-existent session
	notFound, err := store.GetSession(ctx, "non-existent")
	if err != nil {
		t.Fatalf("GetSession for non-existent failed: %v", err)
	}
	if notFound != nil {
		t.Error("expected nil for non-existent session")
	}

	// Test delete session
	if err := store.DeleteSession(ctx, "session-1"); err != nil {
		t.Fatalf("DeleteSession failed: %v", err)
	}

	deleted, err := store.GetSession(ctx, "session-1")
	if err != nil {
		t.Fatalf("GetSession after delete failed: %v", err)
	}
	if deleted != nil {
		t.Error("expected nil after delete")
	}
}

func TestStore_SessionWithNilUserID(t *testing.T) {
	db := setupTestDB(t)
	store := NewStore(db)
	ctx := context.Background()

	// Test create session with nil user ID (for discoverable credentials)
	session := &WebAuthnSession{
		ID:        "session-no-user",
		UserID:    nil,
		Type:      "login",
		Data:      []byte("session-data"),
		ExpiresAt: time.Now().Add(5 * time.Minute),
		CreatedAt: time.Now(),
	}

	if err := store.CreateSession(ctx, session); err != nil {
		t.Fatalf("CreateSession with nil UserID failed: %v", err)
	}

	found, err := store.GetSession(ctx, "session-no-user")
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if found == nil {
		t.Fatal("expected to find session")
	}
	if found.UserID != nil {
		t.Error("expected UserID to be nil")
	}
}

func TestStore_DeleteExpiredSessions(t *testing.T) {
	db := setupTestDB(t)
	store := NewStore(db)
	ctx := context.Background()
	userID := "user-1"

	// Create an expired session
	expired := &WebAuthnSession{
		ID:        "expired-session",
		UserID:    &userID,
		Type:      "register",
		Data:      []byte("data"),
		ExpiresAt: time.Now().Add(-1 * time.Hour),
		CreatedAt: time.Now().Add(-2 * time.Hour),
	}
	if err := store.CreateSession(ctx, expired); err != nil {
		t.Fatalf("CreateSession (expired) failed: %v", err)
	}

	// Create a valid session
	valid := &WebAuthnSession{
		ID:        "valid-session",
		UserID:    &userID,
		Type:      "login",
		Data:      []byte("data"),
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CreatedAt: time.Now(),
	}
	if err := store.CreateSession(ctx, valid); err != nil {
		t.Fatalf("CreateSession (valid) failed: %v", err)
	}

	// Delete expired
	if err := store.DeleteExpiredSessions(ctx); err != nil {
		t.Fatalf("DeleteExpiredSessions failed: %v", err)
	}

	// Check expired is gone
	expiredFound, _ := store.GetSession(ctx, "expired-session")
	if expiredFound != nil {
		t.Error("expected expired session to be deleted")
	}

	// Check valid still exists
	validFound, _ := store.GetSession(ctx, "valid-session")
	if validFound == nil {
		t.Error("expected valid session to still exist")
	}
}

func TestStore_MultipleCredentialsPerUser(t *testing.T) {
	db := setupTestDB(t)
	store := NewStore(db)
	ctx := context.Background()

	// Create multiple credentials for the same user
	for i := 0; i < 3; i++ {
		cred := &WebAuthnCredential{
			ID:           "cred-" + string(rune('a'+i)),
			UserID:       "user-1",
			CredentialID: []byte("credential-id-" + string(rune('a'+i))),
			PublicKey:    []byte("public-key"),
			SignCount:    0,
			CreatedAt:    time.Now(),
		}
		if err := store.CreateCredential(ctx, cred); err != nil {
			t.Fatalf("CreateCredential %d failed: %v", i, err)
		}
	}

	credentials, err := store.ListCredentialsByUser(ctx, "user-1")
	if err != nil {
		t.Fatalf("ListCredentialsByUser failed: %v", err)
	}
	if len(credentials) != 3 {
		t.Errorf("expected 3 credentials, got %d", len(credentials))
	}
}
