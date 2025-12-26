package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
)

func TestCreateVerification(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	verification := &models.Verification{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		TokenHash: "verification-hash-" + uuid.New().String(),
		Type:      models.VerificationTypeEmail,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}

	err := tdb.Store.CreateVerification(ctx, verification)
	if err != nil {
		t.Fatalf("CreateVerification() error = %v", err)
	}

	got, err := tdb.Store.GetVerificationByTokenHash(ctx, verification.TokenHash)
	if err != nil {
		t.Fatalf("GetVerificationByTokenHash() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetVerificationByTokenHash() returned nil")
	}
	if got.ID != verification.ID {
		t.Errorf("GetVerificationByTokenHash().ID = %v, want %v", got.ID, verification.ID)
	}
}

func TestCreateVerification_WithIdentifier(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	identifier := "newemail@example.com"
	verification := &models.Verification{
		ID:         uuid.New().String(),
		UserID:     user.ID,
		TokenHash:  "verification-hash-" + uuid.New().String(),
		Type:       models.VerificationTypeEmailChange,
		Identifier: &identifier,
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		CreatedAt:  time.Now(),
	}

	err := tdb.Store.CreateVerification(ctx, verification)
	if err != nil {
		t.Fatalf("CreateVerification() error = %v", err)
	}

	got, _ := tdb.Store.GetVerificationByTokenHash(ctx, verification.TokenHash)
	if got.Identifier == nil || *got.Identifier != identifier {
		t.Errorf("GetVerificationByTokenHash().Identifier = %v, want %v", got.Identifier, &identifier)
	}
}

func TestCreateVerification_AllTypes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	verificationTypes := []models.VerificationType{
		models.VerificationTypeEmail,
		models.VerificationTypePasswordReset,
		models.VerificationTypeEmailChange,
	}

	for _, vType := range verificationTypes {
		t.Run(string(vType), func(t *testing.T) {
			verification := &models.Verification{
				ID:        uuid.New().String(),
				UserID:    user.ID,
				TokenHash: "hash-" + uuid.New().String(),
				Type:      vType,
				ExpiresAt: time.Now().Add(24 * time.Hour),
				CreatedAt: time.Now(),
			}

			err := tdb.Store.CreateVerification(ctx, verification)
			if err != nil {
				t.Fatalf("CreateVerification(%v) error = %v", vType, err)
			}

			got, _ := tdb.Store.GetVerificationByTokenHash(ctx, verification.TokenHash)
			if got.Type != vType {
				t.Errorf("GetVerificationByTokenHash().Type = %v, want %v", got.Type, vType)
			}
		})
	}
}

func TestGetVerificationByTokenHash(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	tokenHash := "unique-verification-hash-" + uuid.New().String()
	verification := &models.Verification{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		TokenHash: tokenHash,
		Type:      models.VerificationTypePasswordReset,
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CreatedAt: time.Now(),
	}
	_ = tdb.Store.CreateVerification(ctx, verification)

	got, err := tdb.Store.GetVerificationByTokenHash(ctx, tokenHash)
	if err != nil {
		t.Fatalf("GetVerificationByTokenHash() error = %v", err)
	}
	if got == nil {
		t.Fatal("GetVerificationByTokenHash() returned nil")
	}
	if got.Type != models.VerificationTypePasswordReset {
		t.Errorf("GetVerificationByTokenHash().Type = %v, want %v", got.Type, models.VerificationTypePasswordReset)
	}
}

func TestGetVerificationByTokenHash_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)

	got, err := tdb.Store.GetVerificationByTokenHash(ctx, "nonexistent-hash")
	if err != nil {
		t.Fatalf("GetVerificationByTokenHash() error = %v", err)
	}
	if got != nil {
		t.Error("GetVerificationByTokenHash() should return nil for non-existent hash")
	}
}

func TestDeleteVerification(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	tokenHash := "delete-me-" + uuid.New().String()
	verification := &models.Verification{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		TokenHash: tokenHash,
		Type:      models.VerificationTypeEmail,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}
	_ = tdb.Store.CreateVerification(ctx, verification)

	err := tdb.Store.DeleteVerification(ctx, verification.ID)
	if err != nil {
		t.Fatalf("DeleteVerification() error = %v", err)
	}

	got, _ := tdb.Store.GetVerificationByTokenHash(ctx, tokenHash)
	if got != nil {
		t.Error("DeleteVerification() failed to delete verification")
	}
}

func TestDeleteVerification_NonExistent(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)

	err := tdb.Store.DeleteVerification(ctx, "nonexistent-id")
	if err != nil {
		t.Fatalf("DeleteVerification() on non-existent verification should not error, got = %v", err)
	}
}

func TestDeleteVerificationsByUserIDAndType(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	// Create multiple email verifications
	emailHashes := make([]string, 3)
	for i := range 3 {
		hash := "email-hash-" + uuid.New().String()
		emailHashes[i] = hash
		verification := &models.Verification{
			ID:        uuid.New().String(),
			UserID:    user.ID,
			TokenHash: hash,
			Type:      models.VerificationTypeEmail,
			ExpiresAt: time.Now().Add(24 * time.Hour),
			CreatedAt: time.Now(),
		}
		_ = tdb.Store.CreateVerification(ctx, verification)
	}

	// Create a password reset verification
	pwResetHash := "pw-reset-hash-" + uuid.New().String()
	pwVerification := &models.Verification{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		TokenHash: pwResetHash,
		Type:      models.VerificationTypePasswordReset,
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CreatedAt: time.Now(),
	}
	_ = tdb.Store.CreateVerification(ctx, pwVerification)

	// Delete only email verifications
	err := tdb.Store.DeleteVerificationsByUserIDAndType(ctx, user.ID, models.VerificationTypeEmail)
	if err != nil {
		t.Fatalf("DeleteVerificationsByUserIDAndType() error = %v", err)
	}

	// Email verifications should be gone
	for _, hash := range emailHashes {
		got, _ := tdb.Store.GetVerificationByTokenHash(ctx, hash)
		if got != nil {
			t.Errorf("DeleteVerificationsByUserIDAndType() failed to delete email verification with hash %s", hash)
		}
	}

	// Password reset should still exist
	got, _ := tdb.Store.GetVerificationByTokenHash(ctx, pwResetHash)
	if got == nil {
		t.Error("DeleteVerificationsByUserIDAndType() incorrectly deleted password reset verification")
	}
}

func TestDeleteVerificationsByUserIDAndType_DoesNotAffectOtherUsers(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user1 := createTestUser(t, tdb)
	user2 := createTestUser(t, tdb)

	// Create email verification for both users
	user1Hash := "user1-hash-" + uuid.New().String()
	user2Hash := "user2-hash-" + uuid.New().String()

	for _, data := range []struct {
		userID string
		hash   string
	}{
		{user1.ID, user1Hash},
		{user2.ID, user2Hash},
	} {
		verification := &models.Verification{
			ID:        uuid.New().String(),
			UserID:    data.userID,
			TokenHash: data.hash,
			Type:      models.VerificationTypeEmail,
			ExpiresAt: time.Now().Add(24 * time.Hour),
			CreatedAt: time.Now(),
		}
		_ = tdb.Store.CreateVerification(ctx, verification)
	}

	// Delete only user1's email verifications
	_ = tdb.Store.DeleteVerificationsByUserIDAndType(ctx, user1.ID, models.VerificationTypeEmail)

	// user1's verification should be gone
	got, _ := tdb.Store.GetVerificationByTokenHash(ctx, user1Hash)
	if got != nil {
		t.Error("User1's verification should be deleted")
	}

	// user2's verification should still exist
	got, _ = tdb.Store.GetVerificationByTokenHash(ctx, user2Hash)
	if got == nil {
		t.Error("User2's verification should still exist")
	}
}

func TestDeleteExpiredVerifications(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	// Create expired verification
	expiredHash := "expired-" + uuid.New().String()
	expiredV := &models.Verification{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		TokenHash: expiredHash,
		Type:      models.VerificationTypeEmail,
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
		CreatedAt: time.Now().Add(-2 * time.Hour),
	}
	_ = tdb.Store.CreateVerification(ctx, expiredV)

	// Create valid verification
	validHash := "valid-" + uuid.New().String()
	validV := &models.Verification{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		TokenHash: validHash,
		Type:      models.VerificationTypeEmail,
		ExpiresAt: time.Now().Add(24 * time.Hour), // Not expired
		CreatedAt: time.Now(),
	}
	_ = tdb.Store.CreateVerification(ctx, validV)

	err := tdb.Store.DeleteExpiredVerifications(ctx)
	if err != nil {
		t.Fatalf("DeleteExpiredVerifications() error = %v", err)
	}

	// Expired should be gone
	got, _ := tdb.Store.GetVerificationByTokenHash(ctx, expiredHash)
	if got != nil {
		t.Error("DeleteExpiredVerifications() failed to delete expired verification")
	}

	// Valid should still exist
	got, _ = tdb.Store.GetVerificationByTokenHash(ctx, validHash)
	if got == nil {
		t.Error("DeleteExpiredVerifications() incorrectly deleted valid verification")
	}
}

func TestDeleteExpiredVerifications_MultipleTypes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	// Create expired verifications of different types
	expiredTypes := []models.VerificationType{
		models.VerificationTypeEmail,
		models.VerificationTypePasswordReset,
		models.VerificationTypeEmailChange,
	}

	expiredHashes := make([]string, len(expiredTypes))
	for i, vType := range expiredTypes {
		hash := "expired-" + string(vType) + "-" + uuid.New().String()
		expiredHashes[i] = hash
		v := &models.Verification{
			ID:        uuid.New().String(),
			UserID:    user.ID,
			TokenHash: hash,
			Type:      vType,
			ExpiresAt: time.Now().Add(-1 * time.Hour),
			CreatedAt: time.Now().Add(-2 * time.Hour),
		}
		_ = tdb.Store.CreateVerification(ctx, v)
	}

	// Create valid verification
	validHash := "valid-" + uuid.New().String()
	validV := &models.Verification{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		TokenHash: validHash,
		Type:      models.VerificationTypeEmail,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}
	_ = tdb.Store.CreateVerification(ctx, validV)

	err := tdb.Store.DeleteExpiredVerifications(ctx)
	if err != nil {
		t.Fatalf("DeleteExpiredVerifications() error = %v", err)
	}

	// All expired should be gone
	for _, hash := range expiredHashes {
		got, _ := tdb.Store.GetVerificationByTokenHash(ctx, hash)
		if got != nil {
			t.Errorf("DeleteExpiredVerifications() failed to delete expired verification with hash %s", hash)
		}
	}

	// Valid should still exist
	got, _ := tdb.Store.GetVerificationByTokenHash(ctx, validHash)
	if got == nil {
		t.Error("DeleteExpiredVerifications() incorrectly deleted valid verification")
	}
}

func TestDeleteExpiredVerifications_EdgeCase_ExactlyExpired(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()
	tdb.truncateTables(t)
	user := createTestUser(t, tdb)

	// Create verification that just expired (1 second ago)
	justExpiredHash := "just-expired-" + uuid.New().String()
	justExpiredV := &models.Verification{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		TokenHash: justExpiredHash,
		Type:      models.VerificationTypeEmail,
		ExpiresAt: time.Now().Add(-1 * time.Second),
		CreatedAt: time.Now().Add(-1 * time.Hour),
	}
	_ = tdb.Store.CreateVerification(ctx, justExpiredV)

	// Create verification that will expire in 1 second
	almostExpiredHash := "almost-expired-" + uuid.New().String()
	almostExpiredV := &models.Verification{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		TokenHash: almostExpiredHash,
		Type:      models.VerificationTypeEmail,
		ExpiresAt: time.Now().Add(1 * time.Second),
		CreatedAt: time.Now(),
	}
	_ = tdb.Store.CreateVerification(ctx, almostExpiredV)

	err := tdb.Store.DeleteExpiredVerifications(ctx)
	if err != nil {
		t.Fatalf("DeleteExpiredVerifications() error = %v", err)
	}

	// Just expired should be gone
	got, _ := tdb.Store.GetVerificationByTokenHash(ctx, justExpiredHash)
	if got != nil {
		t.Error("DeleteExpiredVerifications() failed to delete just-expired verification")
	}

	// Almost expired should still exist
	got, _ = tdb.Store.GetVerificationByTokenHash(ctx, almostExpiredHash)
	if got == nil {
		t.Error("DeleteExpiredVerifications() incorrectly deleted almost-expired verification")
	}
}
