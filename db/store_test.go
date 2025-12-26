package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
)

// TestUserOperations tests all user-related store operations
func TestUserOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()

	t.Run("CreateUser", func(t *testing.T) {
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
	})

	t.Run("CreateUser_DuplicateEmail", func(t *testing.T) {
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
	})

	t.Run("GetUserByEmail", func(t *testing.T) {
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
	})

	t.Run("GetUserByEmail_NotFound", func(t *testing.T) {
		tdb.truncateTables(t)

		got, err := tdb.Store.GetUserByEmail(ctx, "nonexistent@example.com")
		if err != nil {
			t.Fatalf("GetUserByEmail() error = %v", err)
		}
		if got != nil {
			t.Error("GetUserByEmail() should return nil for non-existent email")
		}
	})

	t.Run("UpdateUser", func(t *testing.T) {
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
	})

	t.Run("SetEmailVerified", func(t *testing.T) {
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
	})

	t.Run("DeleteUser", func(t *testing.T) {
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
	})
}

// TestAccountOperations tests all account-related store operations
func TestAccountOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()

	// Helper to create a user
	createUser := func(t *testing.T) *models.User {
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

	t.Run("CreateAccount_Email", func(t *testing.T) {
		tdb.truncateTables(t)
		user := createUser(t)

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
	})

	t.Run("CreateAccount_WithProviderAccountID", func(t *testing.T) {
		tdb.truncateTables(t)
		user := createUser(t)

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
	})

	t.Run("GetAccountByUserIDAndProvider", func(t *testing.T) {
		tdb.truncateTables(t)
		user := createUser(t)

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
	})

	t.Run("ListAccountsByUserID", func(t *testing.T) {
		tdb.truncateTables(t)
		user := createUser(t)

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
	})

	t.Run("UpdateAccount", func(t *testing.T) {
		tdb.truncateTables(t)
		user := createUser(t)

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
	})

	t.Run("DeleteAccount", func(t *testing.T) {
		tdb.truncateTables(t)
		user := createUser(t)

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
	})

	t.Run("DeleteAccountsByUserID", func(t *testing.T) {
		tdb.truncateTables(t)
		user := createUser(t)

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
	})
}

// TestSessionOperations tests all session-related store operations
func TestSessionOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()

	createUser := func(t *testing.T) *models.User {
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

	t.Run("CreateSession", func(t *testing.T) {
		tdb.truncateTables(t)
		user := createUser(t)

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
	})

	t.Run("GetSessionByTokenHash", func(t *testing.T) {
		tdb.truncateTables(t)
		user := createUser(t)

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
	})

	t.Run("ListSessionsByUserID", func(t *testing.T) {
		tdb.truncateTables(t)
		user := createUser(t)

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
	})

	t.Run("UpdateSessionLastUsed", func(t *testing.T) {
		tdb.truncateTables(t)
		user := createUser(t)

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
	})

	t.Run("DeleteSession", func(t *testing.T) {
		tdb.truncateTables(t)
		user := createUser(t)

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
	})

	t.Run("DeleteSessionsByUserID", func(t *testing.T) {
		tdb.truncateTables(t)
		user := createUser(t)

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
	})

	t.Run("DeleteExpiredSessions", func(t *testing.T) {
		tdb.truncateTables(t)
		user := createUser(t)

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
	})
}

// TestVerificationOperations tests all verification-related store operations
func TestVerificationOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()

	createUser := func(t *testing.T) *models.User {
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

	t.Run("CreateVerification", func(t *testing.T) {
		tdb.truncateTables(t)
		user := createUser(t)

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
	})

	t.Run("GetVerificationByTokenHash", func(t *testing.T) {
		tdb.truncateTables(t)
		user := createUser(t)

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
	})

	t.Run("DeleteVerification", func(t *testing.T) {
		tdb.truncateTables(t)
		user := createUser(t)

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
	})

	t.Run("DeleteVerificationsByUserIDAndType", func(t *testing.T) {
		tdb.truncateTables(t)
		user := createUser(t)

		// Create multiple email verifications
		for range 3 {
			verification := &models.Verification{
				ID:        uuid.New().String(),
				UserID:    user.ID,
				TokenHash: "email-hash-" + uuid.New().String(),
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

		// Password reset should still exist
		got, _ := tdb.Store.GetVerificationByTokenHash(ctx, pwResetHash)
		if got == nil {
			t.Error("DeleteVerificationsByUserIDAndType() incorrectly deleted password reset verification")
		}
	})

	t.Run("DeleteExpiredVerifications", func(t *testing.T) {
		tdb.truncateTables(t)
		user := createUser(t)

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
	})
}

// TestMigrations tests migration functionality
func TestMigrations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()

	t.Run("MigrationStatus", func(t *testing.T) {
		status, err := tdb.Store.MigrationStatus(ctx)
		if err != nil {
			t.Fatalf("MigrationStatus() error = %v", err)
		}

		if len(status) == 0 {
			t.Error("MigrationStatus() returned empty slice")
		}

		// All migrations should be applied
		for _, m := range status {
			if m.MigratedAt.IsZero() {
				t.Errorf("Migration %s is not applied", m.Name)
			}
		}
	})
}
