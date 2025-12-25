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

func setupStateStoreTestDB(t *testing.T) *bun.DB {
	sqldb, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}

	db := bun.NewDB(sqldb, sqlitedialect.New())
	t.Cleanup(func() { db.Close() })

	return db
}

func TestDBStateStore_NewDBStateStore(t *testing.T) {
	db := setupStateStoreTestDB(t)
	store := NewDBStateStore(db)

	if store == nil {
		t.Fatal("NewDBStateStore returned nil")
	}
	if store.db != db {
		t.Error("DBStateStore.db not set correctly")
	}
}

func TestDBStateStore_CreateOAuthState(t *testing.T) {
	db := setupStateStoreTestDB(t)
	store := NewDBStateStore(db)
	ctx := context.Background()

	verifier := "test-verifier"
	redirectTo := "http://localhost/callback"
	state := &State{
		State:      "test-state-123",
		Provider:   "google",
		Verifier:   &verifier,
		RedirectTo: &redirectTo,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(10 * time.Minute),
	}

	err := store.CreateOAuthState(ctx, state)
	if err != nil {
		t.Fatalf("CreateOAuthState failed: %v", err)
	}

	// Verify state was created by retrieving it
	found, err := store.GetOAuthState(ctx, "test-state-123")
	if err != nil {
		t.Fatalf("GetOAuthState failed: %v", err)
	}
	if found == nil {
		t.Fatal("State not found after creation")
	}
	if found.State != "test-state-123" {
		t.Errorf("State = %s, want test-state-123", found.State)
	}
	if found.Provider != "google" {
		t.Errorf("Provider = %s, want google", found.Provider)
	}
	if found.Verifier == nil || *found.Verifier != "test-verifier" {
		t.Error("Verifier not stored correctly")
	}
	if found.RedirectTo == nil || *found.RedirectTo != "http://localhost/callback" {
		t.Error("RedirectTo not stored correctly")
	}
}

func TestDBStateStore_CreateOAuthState_NilOptionalFields(t *testing.T) {
	db := setupStateStoreTestDB(t)
	store := NewDBStateStore(db)
	ctx := context.Background()

	state := &State{
		State:      "state-no-optionals",
		Provider:   "github",
		Verifier:   nil,
		RedirectTo: nil,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(10 * time.Minute),
	}

	err := store.CreateOAuthState(ctx, state)
	if err != nil {
		t.Fatalf("CreateOAuthState failed: %v", err)
	}

	found, err := store.GetOAuthState(ctx, "state-no-optionals")
	if err != nil {
		t.Fatalf("GetOAuthState failed: %v", err)
	}
	if found.Verifier != nil {
		t.Error("Verifier should be nil")
	}
	if found.RedirectTo != nil {
		t.Error("RedirectTo should be nil")
	}
}

func TestDBStateStore_GetOAuthState_NotFound(t *testing.T) {
	db := setupStateStoreTestDB(t)
	store := NewDBStateStore(db)
	ctx := context.Background()

	_, err := store.GetOAuthState(ctx, "nonexistent-state")
	if err == nil {
		t.Error("Expected error for non-existent state, got nil")
	}
}

func TestDBStateStore_DeleteOAuthState(t *testing.T) {
	db := setupStateStoreTestDB(t)
	store := NewDBStateStore(db)
	ctx := context.Background()

	// Create a state first
	state := &State{
		State:     "state-to-delete",
		Provider:  "google",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	err := store.CreateOAuthState(ctx, state)
	if err != nil {
		t.Fatalf("CreateOAuthState failed: %v", err)
	}

	// Verify it exists
	_, err = store.GetOAuthState(ctx, "state-to-delete")
	if err != nil {
		t.Fatalf("State should exist before delete: %v", err)
	}

	// Delete the state
	err = store.DeleteOAuthState(ctx, "state-to-delete")
	if err != nil {
		t.Fatalf("DeleteOAuthState failed: %v", err)
	}

	// Verify it's deleted
	_, err = store.GetOAuthState(ctx, "state-to-delete")
	if err == nil {
		t.Error("State should not exist after delete")
	}
}

func TestDBStateStore_DeleteOAuthState_NonExistent(t *testing.T) {
	db := setupStateStoreTestDB(t)
	store := NewDBStateStore(db)
	ctx := context.Background()

	// Deleting non-existent state should not error
	err := store.DeleteOAuthState(ctx, "nonexistent")
	if err != nil {
		t.Errorf("DeleteOAuthState for non-existent state should not error: %v", err)
	}
}

func TestDBStateStore_DeleteExpiredOAuthStates(t *testing.T) {
	db := setupStateStoreTestDB(t)
	store := NewDBStateStore(db)
	ctx := context.Background()

	now := time.Now()

	// Create expired state
	expiredState := &State{
		State:     "expired-state",
		Provider:  "google",
		CreatedAt: now.Add(-20 * time.Minute),
		ExpiresAt: now.Add(-10 * time.Minute), // Expired 10 minutes ago
	}
	err := store.CreateOAuthState(ctx, expiredState)
	if err != nil {
		t.Fatalf("CreateOAuthState for expired state failed: %v", err)
	}

	// Create valid state
	validState := &State{
		State:     "valid-state",
		Provider:  "github",
		CreatedAt: now,
		ExpiresAt: now.Add(10 * time.Minute), // Expires in 10 minutes
	}
	err = store.CreateOAuthState(ctx, validState)
	if err != nil {
		t.Fatalf("CreateOAuthState for valid state failed: %v", err)
	}

	// Delete expired states
	err = store.DeleteExpiredOAuthStates(ctx)
	if err != nil {
		t.Fatalf("DeleteExpiredOAuthStates failed: %v", err)
	}

	// Verify expired state is deleted
	_, err = store.GetOAuthState(ctx, "expired-state")
	if err == nil {
		t.Error("Expired state should be deleted")
	}

	// Verify valid state still exists
	found, err := store.GetOAuthState(ctx, "valid-state")
	if err != nil {
		t.Fatalf("Valid state should still exist: %v", err)
	}
	if found.State != "valid-state" {
		t.Errorf("State = %s, want valid-state", found.State)
	}
}

func TestDBStateStore_DeleteExpiredOAuthStates_AllExpired(t *testing.T) {
	db := setupStateStoreTestDB(t)
	store := NewDBStateStore(db)
	ctx := context.Background()

	now := time.Now()

	// Create multiple expired states
	for i, name := range []string{"expired-1", "expired-2", "expired-3"} {
		state := &State{
			State:     name,
			Provider:  "google",
			CreatedAt: now.Add(-20 * time.Minute),
			ExpiresAt: now.Add(time.Duration(-10-i) * time.Minute),
		}
		if err := store.CreateOAuthState(ctx, state); err != nil {
			t.Fatalf("CreateOAuthState failed: %v", err)
		}
	}

	// Delete expired states
	err := store.DeleteExpiredOAuthStates(ctx)
	if err != nil {
		t.Fatalf("DeleteExpiredOAuthStates failed: %v", err)
	}

	// Verify all are deleted
	for _, name := range []string{"expired-1", "expired-2", "expired-3"} {
		_, err := store.GetOAuthState(ctx, name)
		if err == nil {
			t.Errorf("State %s should be deleted", name)
		}
	}
}

func TestDBStateStore_DeleteExpiredOAuthStates_NoneExpired(t *testing.T) {
	db := setupStateStoreTestDB(t)
	store := NewDBStateStore(db)
	ctx := context.Background()

	now := time.Now()

	// Create only valid states
	for _, name := range []string{"valid-1", "valid-2"} {
		state := &State{
			State:     name,
			Provider:  "google",
			CreatedAt: now,
			ExpiresAt: now.Add(10 * time.Minute),
		}
		if err := store.CreateOAuthState(ctx, state); err != nil {
			t.Fatalf("CreateOAuthState failed: %v", err)
		}
	}

	// Delete expired states (should do nothing)
	err := store.DeleteExpiredOAuthStates(ctx)
	if err != nil {
		t.Fatalf("DeleteExpiredOAuthStates failed: %v", err)
	}

	// Verify all valid states still exist
	for _, name := range []string{"valid-1", "valid-2"} {
		_, err := store.GetOAuthState(ctx, name)
		if err != nil {
			t.Errorf("State %s should still exist: %v", name, err)
		}
	}
}

func TestDBStateStore_EnsureTable_Idempotent(t *testing.T) {
	db := setupStateStoreTestDB(t)
	store := NewDBStateStore(db)
	ctx := context.Background()

	// Create state multiple times (each call triggers ensureTable)
	for i := 0; i < 3; i++ {
		state := &State{
			State:     "state-" + string(rune('a'+i)),
			Provider:  "google",
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(10 * time.Minute),
		}
		err := store.CreateOAuthState(ctx, state)
		if err != nil {
			t.Fatalf("CreateOAuthState iteration %d failed: %v", i, err)
		}
	}

	// Verify all states exist
	for i := 0; i < 3; i++ {
		name := "state-" + string(rune('a'+i))
		_, err := store.GetOAuthState(ctx, name)
		if err != nil {
			t.Errorf("State %s should exist: %v", name, err)
		}
	}
}
