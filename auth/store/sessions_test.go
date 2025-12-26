package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
)

func createTestUser(t *testing.T, tdb *testDB) *models.User {
	t.Helper()
	ctx := context.Background()
	user := &models.User{
		ID:        uuid.New().String(),
		Email:     uuid.New().String() + "@example.com",
		Name:      "Test User",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := tdb.Store.CreateUser(ctx, user); err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}
	return user
}

func TestCreateSession(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	ipAddr := "192.168.1.1"
	userAgent := "Mozilla/5.0"
	session := &models.Session{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		TokenHash: "hash-" + uuid.New().String(),
		IPAddress: &ipAddr,
		UserAgent: &userAgent,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		LastUsed:  time.Now(),
	}

	err := tdb.Store.CreateSession(ctx, session)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	got, err := tdb.Store.GetSessionByID(ctx, session.ID)
	if err != nil {
		t.Fatalf("GetSessionByID() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetSessionByID() returned nil")
	}
	if got.UserID != user.ID {
		t.Errorf("GetSessionByID().UserID = %v, want %v", got.UserID, user.ID)
	}
}

func TestCreateSession_WithoutOptionalFields(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	session := &models.Session{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		TokenHash: "hash-" + uuid.New().String(),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		LastUsed:  time.Now(),
	}

	err := tdb.Store.CreateSession(ctx, session)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	got, _ := tdb.Store.GetSessionByID(ctx, session.ID)
	if got.IPAddress != nil {
		t.Errorf("GetSessionByID().IPAddress should be nil, got %v", got.IPAddress)
	}
	if got.UserAgent != nil {
		t.Errorf("GetSessionByID().UserAgent should be nil, got %v", got.UserAgent)
	}
}

func TestGetSessionByID(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	session := &models.Session{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		TokenHash: "hash-" + uuid.New().String(),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		LastUsed:  time.Now(),
	}
	_ = tdb.Store.CreateSession(ctx, session)

	got, err := tdb.Store.GetSessionByID(ctx, session.ID)
	if err != nil {
		t.Fatalf("GetSessionByID() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetSessionByID() returned nil")
	}
	if got.ID != session.ID {
		t.Errorf("GetSessionByID().ID = %v, want %v", got.ID, session.ID)
	}
}

func TestGetSessionByID_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)

	got, err := tdb.Store.GetSessionByID(ctx, "nonexistent-id")
	if err != nil {
		t.Fatalf("GetSessionByID() error = %v", err)
	}
	if got != nil {
		t.Error("GetSessionByID() should return nil for non-existent ID")
	}
}

func TestGetSessionByTokenHash(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	tokenHash := "unique-token-hash-" + uuid.New().String()
	session := &models.Session{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		TokenHash: tokenHash,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		LastUsed:  time.Now(),
	}
	_ = tdb.Store.CreateSession(ctx, session)

	got, err := tdb.Store.GetSessionByTokenHash(ctx, tokenHash)
	if err != nil {
		t.Fatalf("GetSessionByTokenHash() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetSessionByTokenHash() returned nil")
	}
	if got.ID != session.ID {
		t.Errorf("GetSessionByTokenHash().ID = %v, want %v", got.ID, session.ID)
	}
}

func TestGetSessionByTokenHash_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)

	got, err := tdb.Store.GetSessionByTokenHash(ctx, "nonexistent-hash")
	if err != nil {
		t.Fatalf("GetSessionByTokenHash() error = %v", err)
	}
	if got != nil {
		t.Error("GetSessionByTokenHash() should return nil for non-existent hash")
	}
}

func TestListSessionsByUserID(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	// Create multiple sessions
	for range 3 {
		session := &models.Session{
			ID:        uuid.New().String(),
			UserID:    user.ID,
			TokenHash: "hash-" + uuid.New().String(),
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
			LastUsed:  time.Now(),
		}
		_ = tdb.Store.CreateSession(ctx, session)
	}

	sessions, err := tdb.Store.ListSessionsByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUserID() error = %v", err)
	}
	if len(sessions) != 3 {
		t.Errorf("ListSessionsByUserID() returned %d sessions, want 3", len(sessions))
	}
}

func TestListSessionsByUserID_Empty(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	sessions, err := tdb.Store.ListSessionsByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListSessionsByUserID() error = %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("ListSessionsByUserID() returned %d sessions, want 0", len(sessions))
	}
}

func TestListSessionsByUserID_OrderedByCreatedAt(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	// Create sessions with different created times
	now := time.Now()
	times := []time.Time{
		now.Add(-2 * time.Hour),
		now.Add(-1 * time.Hour),
		now,
	}

	for i, createdAt := range times {
		session := &models.Session{
			ID:        uuid.New().String(),
			UserID:    user.ID,
			TokenHash: "hash-" + uuid.New().String(),
			CreatedAt: createdAt,
			ExpiresAt: now.Add(24 * time.Hour),
			LastUsed:  createdAt,
		}
		_ = tdb.Store.CreateSession(ctx, session)
		if i < len(times)-1 {
			time.Sleep(10 * time.Millisecond) // Ensure different timestamps
		}
	}

	sessions, _ := tdb.Store.ListSessionsByUserID(ctx, user.ID)
	if len(sessions) != 3 {
		t.Fatalf("ListSessionsByUserID() returned %d sessions, want 3", len(sessions))
	}

	// Should be ordered by created_at DESC (newest first)
	for i := 0; i < len(sessions)-1; i++ {
		if sessions[i].CreatedAt.Before(sessions[i+1].CreatedAt) {
			t.Errorf("Sessions not ordered by created_at DESC: session %d (%v) before session %d (%v)",
				i, sessions[i].CreatedAt, i+1, sessions[i+1].CreatedAt)
		}
	}
}

func TestUpdateSessionLastUsed(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	originalTime := time.Now().Add(-1 * time.Hour)
	session := &models.Session{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		TokenHash: "hash-" + uuid.New().String(),
		CreatedAt: originalTime,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		LastUsed:  originalTime,
	}
	_ = tdb.Store.CreateSession(ctx, session)

	err := tdb.Store.UpdateSessionLastUsed(ctx, session.ID)
	if err != nil {
		t.Fatalf("UpdateSessionLastUsed() error = %v", err)
	}

	got, _ := tdb.Store.GetSessionByID(ctx, session.ID)
	if got.LastUsed.Before(originalTime.Add(30 * time.Minute)) {
		t.Error("UpdateSessionLastUsed() did not update last_used")
	}
}

func TestDeleteSession(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	session := &models.Session{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		TokenHash: "hash-" + uuid.New().String(),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		LastUsed:  time.Now(),
	}
	_ = tdb.Store.CreateSession(ctx, session)

	err := tdb.Store.DeleteSession(ctx, session.ID)
	if err != nil {
		t.Fatalf("DeleteSession() error = %v", err)
	}

	got, _ := tdb.Store.GetSessionByID(ctx, session.ID)
	if got != nil {
		t.Error("DeleteSession() failed to delete session")
	}
}

func TestDeleteSession_NonExistent(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)

	err := tdb.Store.DeleteSession(ctx, "nonexistent-id")
	if err != nil {
		t.Fatalf("DeleteSession() on non-existent session should not error, got = %v", err)
	}
}

func TestDeleteSessionsByUserID(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	for range 3 {
		session := &models.Session{
			ID:        uuid.New().String(),
			UserID:    user.ID,
			TokenHash: "hash-" + uuid.New().String(),
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
			LastUsed:  time.Now(),
		}
		_ = tdb.Store.CreateSession(ctx, session)
	}

	err := tdb.Store.DeleteSessionsByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("DeleteSessionsByUserID() error = %v", err)
	}

	sessions, _ := tdb.Store.ListSessionsByUserID(ctx, user.ID)
	if len(sessions) != 0 {
		t.Errorf("DeleteSessionsByUserID() left %d sessions", len(sessions))
	}
}

func TestDeleteSessionsByUserID_DoesNotAffectOtherUsers(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user1 := createTestUser(t, tdb)
	user2 := createTestUser(t, tdb)

	// Create sessions for both users
	for _, user := range []*models.User{user1, user2} {
		session := &models.Session{
			ID:        uuid.New().String(),
			UserID:    user.ID,
			TokenHash: "hash-" + uuid.New().String(),
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
			LastUsed:  time.Now(),
		}
		_ = tdb.Store.CreateSession(ctx, session)
	}

	// Delete only user1's sessions
	_ = tdb.Store.DeleteSessionsByUserID(ctx, user1.ID)

	// user1 should have no sessions
	sessions1, _ := tdb.Store.ListSessionsByUserID(ctx, user1.ID)
	if len(sessions1) != 0 {
		t.Errorf("User1 should have 0 sessions, got %d", len(sessions1))
	}

	// user2 should still have their session
	sessions2, _ := tdb.Store.ListSessionsByUserID(ctx, user2.ID)
	if len(sessions2) != 1 {
		t.Errorf("User2 should have 1 session, got %d", len(sessions2))
	}
}

func TestDeleteExpiredSessions(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	// Create expired session
	expiredSession := &models.Session{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		TokenHash: "expired-" + uuid.New().String(),
		CreatedAt: time.Now().Add(-48 * time.Hour),
		ExpiresAt: time.Now().Add(-24 * time.Hour), // Expired
		LastUsed:  time.Now().Add(-48 * time.Hour),
	}
	_ = tdb.Store.CreateSession(ctx, expiredSession)

	// Create valid session
	validSession := &models.Session{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		TokenHash: "valid-" + uuid.New().String(),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour), // Not expired
		LastUsed:  time.Now(),
	}
	_ = tdb.Store.CreateSession(ctx, validSession)

	err := tdb.Store.DeleteExpiredSessions(ctx)
	if err != nil {
		t.Fatalf("DeleteExpiredSessions() error = %v", err)
	}

	// Expired should be gone
	got, _ := tdb.Store.GetSessionByID(ctx, expiredSession.ID)
	if got != nil {
		t.Error("DeleteExpiredSessions() failed to delete expired session")
	}

	// Valid should still exist
	got, _ = tdb.Store.GetSessionByID(ctx, validSession.ID)
	if got == nil {
		t.Error("DeleteExpiredSessions() incorrectly deleted valid session")
	}
}

func TestDeleteExpiredSessions_MultipleSessions(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	// Create 5 expired sessions
	for range 5 {
		session := &models.Session{
			ID:        uuid.New().String(),
			UserID:    user.ID,
			TokenHash: "expired-" + uuid.New().String(),
			CreatedAt: time.Now().Add(-48 * time.Hour),
			ExpiresAt: time.Now().Add(-24 * time.Hour),
			LastUsed:  time.Now().Add(-48 * time.Hour),
		}
		_ = tdb.Store.CreateSession(ctx, session)
	}

	// Create 3 valid sessions
	for range 3 {
		session := &models.Session{
			ID:        uuid.New().String(),
			UserID:    user.ID,
			TokenHash: "valid-" + uuid.New().String(),
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
			LastUsed:  time.Now(),
		}
		_ = tdb.Store.CreateSession(ctx, session)
	}

	err := tdb.Store.DeleteExpiredSessions(ctx)
	if err != nil {
		t.Fatalf("DeleteExpiredSessions() error = %v", err)
	}

	sessions, _ := tdb.Store.ListSessionsByUserID(ctx, user.ID)
	if len(sessions) != 3 {
		t.Errorf("DeleteExpiredSessions() should leave 3 valid sessions, got %d", len(sessions))
	}
}
