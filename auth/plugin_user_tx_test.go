package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
	"github.com/webdeveloperben/BetterAuthGoServer/db"
)

// Stores without transaction support get a nil tx, and a failing fn leaves no user behind.
func TestCreatePluginUserTx_WithoutTransactions_RemovesUserOnFailure(t *testing.T) {
	a, store := createTestAuth(t)
	defer a.Close()

	linkErr := errors.New("link failed")
	_, err := a.CreatePluginUserTx(context.Background(), plugin.CreateUserRequest{
		Email: "orphan@example.com", Name: "Orphan", EmailVerified: true,
	}, func(_ context.Context, tx db.DBTX, user *plugin.User) error {
		assert.Nil(t, tx)
		assert.NotEmpty(t, store.users[user.ID], "user exists while fn runs")
		return linkErr
	})

	require.ErrorIs(t, err, linkErr)
	assert.Empty(t, store.users)
}

func TestCreatePluginUserTx_WithoutTransactions_Success(t *testing.T) {
	a, store := createTestAuth(t)
	defer a.Close()

	user, err := a.CreatePluginUserTx(context.Background(), plugin.CreateUserRequest{
		Email: "new@example.com", Name: "New", EmailVerified: true,
	}, func(context.Context, db.DBTX, *plugin.User) error { return nil })

	require.NoError(t, err)
	require.Contains(t, store.users, user.ID)
	assert.True(t, store.users[user.ID].EmailVerified)
}

func TestCreatePluginUserTx_ExistingEmail(t *testing.T) {
	a, store := createTestAuth(t)
	defer a.Close()
	store.users["existing"] = &models.User{ID: "existing", Email: "taken@example.com"}

	called := false
	_, err := a.CreatePluginUserTx(context.Background(), plugin.CreateUserRequest{Email: "taken@example.com"},
		func(context.Context, db.DBTX, *plugin.User) error { called = true; return nil })

	require.ErrorIs(t, err, models.ErrUserAlreadyExists)
	assert.False(t, called)
	assert.Len(t, store.users, 1)
}
