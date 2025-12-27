package apikey_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/apikey"
)

func TestService_Create(t *testing.T) {
	service, _ := setupTestService(t)
	ctx := context.Background()
	userID := "user-123"

	t.Run("creates key with defaults", func(t *testing.T) {
		result, err := service.Create(ctx, userID, apikey.CreateRequest{})
		require.NoError(t, err)

		assert.NotEmpty(t, result.Key.ID)
		assert.NotEmpty(t, result.RawKey)
		assert.Equal(t, userID, result.Key.UserID)
		assert.Equal(t, 6, len(result.Key.Start))
		assert.True(t, result.Key.Enabled)
		assert.True(t, result.Key.RateLimitEnabled)
	})

	t.Run("creates key with name", func(t *testing.T) {
		name := "my-api-key"
		result, err := service.Create(ctx, userID, apikey.CreateRequest{
			Name: &name,
		})
		require.NoError(t, err)

		assert.Equal(t, &name, result.Key.Name)
	})

	t.Run("creates key with prefix", func(t *testing.T) {
		prefix := "myapp"
		result, err := service.Create(ctx, userID, apikey.CreateRequest{
			Prefix: &prefix,
		})
		require.NoError(t, err)

		assert.Equal(t, &prefix, result.Key.Prefix)
		assert.Contains(t, result.RawKey, "myapp_")
	})

	t.Run("creates key with expiration", func(t *testing.T) {
		expiresIn := int64(3600000) // 1 hour in ms
		result, err := service.Create(ctx, userID, apikey.CreateRequest{
			ExpiresIn: &expiresIn,
		})
		require.NoError(t, err)

		assert.NotNil(t, result.Key.ExpiresAt)
		assert.True(t, result.Key.ExpiresAt.After(time.Now()))
	})

	t.Run("creates key with permissions", func(t *testing.T) {
		perms := apikey.Permissions{
			"files": {"read", "write"},
			"users": {"read"},
		}
		result, err := service.Create(ctx, userID, apikey.CreateRequest{
			Permissions: perms,
		})
		require.NoError(t, err)

		assert.NotNil(t, result.Key)
	})

	t.Run("creates key with remaining count", func(t *testing.T) {
		remaining := 100
		result, err := service.Create(ctx, userID, apikey.CreateRequest{
			Remaining: &remaining,
		})
		require.NoError(t, err)

		assert.Equal(t, &remaining, result.Key.Remaining)
	})

	t.Run("creates key with metadata", func(t *testing.T) {
		metadata := apikey.Metadata{
			"environment": "production",
			"team":        "backend",
		}
		result, err := service.Create(ctx, userID, apikey.CreateRequest{
			Metadata: metadata,
		})
		require.NoError(t, err)

		assert.NotNil(t, result.Key)
	})

	t.Run("creates key with rate limit overrides", func(t *testing.T) {
		enabled := true
		window := int64(60000) // 1 minute
		max := 5
		result, err := service.Create(ctx, userID, apikey.CreateRequest{
			RateLimitEnabled:    &enabled,
			RateLimitTimeWindow: &window,
			RateLimitMax:        &max,
		})
		require.NoError(t, err)

		assert.True(t, result.Key.RateLimitEnabled)
		assert.Equal(t, window, result.Key.RateLimitTimeWindow)
		assert.Equal(t, max, result.Key.RateLimitMax)
	})

	t.Run("rejects invalid prefix length", func(t *testing.T) {
		prefix := "" // Too short
		_, err := service.Create(ctx, userID, apikey.CreateRequest{
			Prefix: &prefix,
		})
		assert.ErrorIs(t, err, apikey.ErrInvalidPrefix)
	})

	t.Run("rejects invalid name length", func(t *testing.T) {
		name := "" // Too short
		_, err := service.Create(ctx, userID, apikey.CreateRequest{
			Name: &name,
		})
		assert.ErrorIs(t, err, apikey.ErrInvalidName)
	})
}

func TestService_VerifyKey(t *testing.T) {
	service, _ := setupTestService(t)
	ctx := context.Background()
	userID := "user-123"

	t.Run("verifies valid key", func(t *testing.T) {
		result, err := service.Create(ctx, userID, apikey.CreateRequest{})
		require.NoError(t, err)

		key, err := service.VerifyKey(ctx, result.RawKey, nil)
		require.NoError(t, err)

		assert.Equal(t, result.Key.ID, key.ID)
	})

	t.Run("verifies key with prefix", func(t *testing.T) {
		prefix := "testapp"
		result, err := service.Create(ctx, userID, apikey.CreateRequest{
			Prefix: &prefix,
		})
		require.NoError(t, err)

		key, err := service.VerifyKey(ctx, result.RawKey, nil)
		require.NoError(t, err)

		assert.Equal(t, result.Key.ID, key.ID)
	})

	t.Run("rejects invalid key", func(t *testing.T) {
		_, err := service.VerifyKey(ctx, "invalid-key", nil)
		assert.ErrorIs(t, err, apikey.ErrInvalidAPIKey)
	})

	t.Run("rejects disabled key", func(t *testing.T) {
		result, err := service.Create(ctx, userID, apikey.CreateRequest{})
		require.NoError(t, err)

		// Disable the key
		enabled := false
		_, err = service.Update(ctx, result.Key.ID, userID, apikey.UpdateRequest{
			Enabled: &enabled,
		})
		require.NoError(t, err)

		_, err = service.VerifyKey(ctx, result.RawKey, nil)
		assert.ErrorIs(t, err, apikey.ErrInvalidAPIKey) // Returns invalid, not disabled, to prevent enumeration
	})

	t.Run("rejects expired key", func(t *testing.T) {
		expiresIn := int64(1) // 1ms - will expire immediately
		result, err := service.Create(ctx, userID, apikey.CreateRequest{
			ExpiresIn: &expiresIn,
		})
		require.NoError(t, err)

		time.Sleep(10 * time.Millisecond)

		_, err = service.VerifyKey(ctx, result.RawKey, nil)
		assert.ErrorIs(t, err, apikey.ErrExpiredAPIKey)
	})

	t.Run("checks permissions - granted", func(t *testing.T) {
		perms := apikey.Permissions{
			"files": {"read", "write"},
		}
		result, err := service.Create(ctx, userID, apikey.CreateRequest{
			Permissions: perms,
		})
		require.NoError(t, err)

		key, err := service.VerifyKey(ctx, result.RawKey, apikey.Permissions{
			"files": {"read"},
		})
		require.NoError(t, err)
		assert.NotNil(t, key)
	})

	t.Run("checks permissions - denied", func(t *testing.T) {
		perms := apikey.Permissions{
			"files": {"read"},
		}
		result, err := service.Create(ctx, userID, apikey.CreateRequest{
			Permissions: perms,
		})
		require.NoError(t, err)

		_, err = service.VerifyKey(ctx, result.RawKey, apikey.Permissions{
			"files": {"write"},
		})
		assert.ErrorIs(t, err, apikey.ErrInsufficientPerms)
	})

	t.Run("decrements remaining count", func(t *testing.T) {
		remaining := 2
		result, err := service.Create(ctx, userID, apikey.CreateRequest{
			Remaining: &remaining,
		})
		require.NoError(t, err)

		// First use
		key, err := service.VerifyKey(ctx, result.RawKey, nil)
		require.NoError(t, err)
		assert.Equal(t, 1, *key.Remaining)

		// Second use
		key, err = service.VerifyKey(ctx, result.RawKey, nil)
		require.NoError(t, err)
		assert.Equal(t, 0, *key.Remaining)

		// Third use - should fail
		_, err = service.VerifyKey(ctx, result.RawKey, nil)
		assert.ErrorIs(t, err, apikey.ErrNoRemainingUses)
	})

	t.Run("unlimited remaining when nil", func(t *testing.T) {
		result, err := service.Create(ctx, userID, apikey.CreateRequest{})
		require.NoError(t, err)

		// Multiple uses should succeed
		for i := 0; i < 5; i++ {
			_, err = service.VerifyKey(ctx, result.RawKey, nil)
			require.NoError(t, err)
		}
	})
}

func TestService_List(t *testing.T) {
	service, _ := setupTestService(t)
	ctx := context.Background()
	userID := "user-list-test"
	otherUserID := "other-user"

	t.Run("returns user keys", func(t *testing.T) {
		// Create keys for user
		_, err := service.Create(ctx, userID, apikey.CreateRequest{})
		require.NoError(t, err)
		_, err = service.Create(ctx, userID, apikey.CreateRequest{})
		require.NoError(t, err)

		// Create key for other user
		_, err = service.Create(ctx, otherUserID, apikey.CreateRequest{})
		require.NoError(t, err)

		keys, err := service.List(ctx, userID)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(keys), 2)

		// All keys should belong to user
		for _, key := range keys {
			assert.Equal(t, userID, key.UserID)
		}
	})

	t.Run("returns empty for user with no keys", func(t *testing.T) {
		keys, err := service.List(ctx, "nonexistent-user")
		require.NoError(t, err)
		assert.Empty(t, keys)
	})
}

func TestService_Get(t *testing.T) {
	service, _ := setupTestService(t)
	ctx := context.Background()
	userID := "user-get-test"

	t.Run("returns key by ID", func(t *testing.T) {
		result, err := service.Create(ctx, userID, apikey.CreateRequest{})
		require.NoError(t, err)

		key, err := service.GetByIDAndUser(ctx, result.Key.ID, userID)
		require.NoError(t, err)
		assert.Equal(t, result.Key.ID, key.ID)
	})

	t.Run("fails for wrong user", func(t *testing.T) {
		result, err := service.Create(ctx, userID, apikey.CreateRequest{})
		require.NoError(t, err)

		_, err = service.GetByIDAndUser(ctx, result.Key.ID, "other-user")
		assert.ErrorIs(t, err, apikey.ErrKeyNotFound)
	})

	t.Run("fails for nonexistent key", func(t *testing.T) {
		_, err := service.GetByIDAndUser(ctx, "nonexistent-id", userID)
		assert.ErrorIs(t, err, apikey.ErrKeyNotFound)
	})
}

func TestService_Update(t *testing.T) {
	service, _ := setupTestService(t)
	ctx := context.Background()
	userID := "user-update-test"

	t.Run("updates name", func(t *testing.T) {
		result, err := service.Create(ctx, userID, apikey.CreateRequest{})
		require.NoError(t, err)

		name := "updated-name"
		updated, err := service.Update(ctx, result.Key.ID, userID, apikey.UpdateRequest{
			Name: &name,
		})
		require.NoError(t, err)
		assert.Equal(t, &name, updated.Name)
	})

	t.Run("updates enabled", func(t *testing.T) {
		result, err := service.Create(ctx, userID, apikey.CreateRequest{})
		require.NoError(t, err)

		enabled := false
		updated, err := service.Update(ctx, result.Key.ID, userID, apikey.UpdateRequest{
			Enabled: &enabled,
		})
		require.NoError(t, err)
		assert.False(t, updated.Enabled)
	})

	t.Run("updates rate limit settings", func(t *testing.T) {
		result, err := service.Create(ctx, userID, apikey.CreateRequest{})
		require.NoError(t, err)

		enabled := false
		window := int64(30000)
		max := 50
		updated, err := service.Update(ctx, result.Key.ID, userID, apikey.UpdateRequest{
			RateLimitEnabled:    &enabled,
			RateLimitTimeWindow: &window,
			RateLimitMax:        &max,
		})
		require.NoError(t, err)
		assert.False(t, updated.RateLimitEnabled)
		assert.Equal(t, window, updated.RateLimitTimeWindow)
		assert.Equal(t, max, updated.RateLimitMax)
	})

	t.Run("updates remaining", func(t *testing.T) {
		result, err := service.Create(ctx, userID, apikey.CreateRequest{})
		require.NoError(t, err)

		remaining := 500
		updated, err := service.Update(ctx, result.Key.ID, userID, apikey.UpdateRequest{
			Remaining: &remaining,
		})
		require.NoError(t, err)
		assert.Equal(t, &remaining, updated.Remaining)
	})

	t.Run("updates expiration", func(t *testing.T) {
		result, err := service.Create(ctx, userID, apikey.CreateRequest{})
		require.NoError(t, err)

		expiresIn := int64(7200000) // 2 hours
		updated, err := service.Update(ctx, result.Key.ID, userID, apikey.UpdateRequest{
			ExpiresIn: &expiresIn,
		})
		require.NoError(t, err)
		assert.NotNil(t, updated.ExpiresAt)
	})

	t.Run("fails for wrong user", func(t *testing.T) {
		result, err := service.Create(ctx, userID, apikey.CreateRequest{})
		require.NoError(t, err)

		name := "hacker"
		_, err = service.Update(ctx, result.Key.ID, "other-user", apikey.UpdateRequest{
			Name: &name,
		})
		assert.ErrorIs(t, err, apikey.ErrKeyNotFound)
	})

	t.Run("fails for invalid name", func(t *testing.T) {
		result, err := service.Create(ctx, userID, apikey.CreateRequest{})
		require.NoError(t, err)

		name := "" // Too short
		_, err = service.Update(ctx, result.Key.ID, userID, apikey.UpdateRequest{
			Name: &name,
		})
		assert.ErrorIs(t, err, apikey.ErrInvalidName)
	})
}

func TestService_Delete(t *testing.T) {
	service, _ := setupTestService(t)
	ctx := context.Background()
	userID := "user-delete-test"

	t.Run("deletes key", func(t *testing.T) {
		result, err := service.Create(ctx, userID, apikey.CreateRequest{})
		require.NoError(t, err)

		err = service.Delete(ctx, result.Key.ID, userID)
		require.NoError(t, err)

		_, err = service.GetByIDAndUser(ctx, result.Key.ID, userID)
		assert.ErrorIs(t, err, apikey.ErrKeyNotFound)
	})

	t.Run("fails for wrong user", func(t *testing.T) {
		result, err := service.Create(ctx, userID, apikey.CreateRequest{})
		require.NoError(t, err)

		err = service.Delete(ctx, result.Key.ID, "other-user")
		assert.ErrorIs(t, err, apikey.ErrKeyNotFound)
	})

	t.Run("fails for nonexistent key", func(t *testing.T) {
		err := service.Delete(ctx, "nonexistent-id", userID)
		assert.ErrorIs(t, err, apikey.ErrKeyNotFound)
	})
}

func TestService_DeleteAllExpired(t *testing.T) {
	service, _ := setupTestService(t)
	ctx := context.Background()
	userID := "user-expired-test"

	t.Run("deletes expired keys", func(t *testing.T) {
		// Create expired key
		expiresIn := int64(1) // 1ms
		_, err := service.Create(ctx, userID, apikey.CreateRequest{
			ExpiresIn: &expiresIn,
		})
		require.NoError(t, err)

		// Create non-expired key
		longExpiry := int64(3600000) // 1 hour
		result, err := service.Create(ctx, userID, apikey.CreateRequest{
			ExpiresIn: &longExpiry,
		})
		require.NoError(t, err)

		time.Sleep(10 * time.Millisecond)

		deleted, err := service.DeleteAllExpired(ctx)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, deleted, int64(1))

		// Non-expired key should still exist
		_, err = service.GetByIDAndUser(ctx, result.Key.ID, userID)
		require.NoError(t, err)
	})
}

func TestService_GetPermissions(t *testing.T) {
	service, _ := setupTestService(t)
	ctx := context.Background()
	userID := "user-perms-test"

	t.Run("returns permissions", func(t *testing.T) {
		perms := apikey.Permissions{
			"files": {"read", "write"},
			"users": {"read"},
		}
		result, err := service.Create(ctx, userID, apikey.CreateRequest{
			Permissions: perms,
		})
		require.NoError(t, err)

		gotPerms, err := service.GetPermissions(result.Key)
		require.NoError(t, err)
		assert.True(t, gotPerms.HasPermission("files", "read"))
		assert.True(t, gotPerms.HasPermission("files", "write"))
		assert.True(t, gotPerms.HasPermission("users", "read"))
	})

	t.Run("returns nil for no permissions", func(t *testing.T) {
		result, err := service.Create(ctx, userID, apikey.CreateRequest{})
		require.NoError(t, err)

		gotPerms, err := service.GetPermissions(result.Key)
		require.NoError(t, err)
		assert.Nil(t, gotPerms)
	})
}

func TestService_GetMetadata(t *testing.T) {
	service, _ := setupTestService(t)
	ctx := context.Background()
	userID := "user-meta-test"

	t.Run("returns metadata", func(t *testing.T) {
		meta := apikey.Metadata{
			"environment": "production",
			"team":        "backend",
		}
		result, err := service.Create(ctx, userID, apikey.CreateRequest{
			Metadata: meta,
		})
		require.NoError(t, err)

		gotMeta, err := service.GetMetadata(result.Key)
		require.NoError(t, err)
		assert.Equal(t, "production", gotMeta["environment"])
		assert.Equal(t, "backend", gotMeta["team"])
	})

	t.Run("returns nil for no metadata", func(t *testing.T) {
		result, err := service.Create(ctx, userID, apikey.CreateRequest{})
		require.NoError(t, err)

		gotMeta, err := service.GetMetadata(result.Key)
		require.NoError(t, err)
		assert.Nil(t, gotMeta)
	})
}
