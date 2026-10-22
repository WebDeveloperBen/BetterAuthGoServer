package e2e

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/oauth"
)

// Deleting a user removes their OAuth identities and pending link states, so the same
// provider identity can sign up again afterwards.
func TestDeletedUserOAuthIdentityCanSignUpAgain(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	for _, dialectEnv := range GetDialects() {
		t.Run(string(dialectEnv.Dialect), func(t *testing.T) {
			env := setupOAuth(t, dialectEnv)
			defer env.Cleanup(t)

			info := oauth.UserInfo{ID: "idp-kate", Email: "kate@example.com", EmailVerified: true, Name: "Kate"}

			t.Run("SelfServiceDelete", func(t *testing.T) {
				env.TruncateTables(t)
				cookies := env.signInWithIDP(t, "code-kate-1", info)
				oldID := env.userID(t, "kate@example.com")
				env.beginLink(t, "", cookies) // a pending link state bound to the user

				resp := env.do(t, http.MethodDelete, "/auth/account", cookies)
				_ = resp.Body.Close()
				require.Equal(t, http.StatusNoContent, resp.StatusCode)

				assert.Zero(t, env.count(t, "SELECT COUNT(*) FROM users"))
				assert.Zero(t, env.count(t, "SELECT COUNT(*) FROM oauth_accounts WHERE user_id = ?", oldID))
				assert.Zero(t, env.count(t, "SELECT COUNT(*) FROM oauth_states WHERE link_user_id = ?", oldID))

				env.signInWithIDP(t, "code-kate-2", info)
				newID := env.userID(t, "kate@example.com")
				assert.NotEqual(t, oldID, newID)
				assert.Equal(t, newID, env.accountOwner(t, "idp-kate"))
			})

			t.Run("AdminDelete", func(t *testing.T) {
				env.TruncateTables(t)
				env.signInWithIDP(t, "code-kate-3", info)
				oldID := env.userID(t, "kate@example.com")

				require.NoError(t, env.Store.AdminDeleteUser(context.Background(), oldID))
				assert.Zero(t, env.count(t, "SELECT COUNT(*) FROM oauth_accounts"))

				env.signInWithIDP(t, "code-kate-4", info)
				assert.Equal(t, env.userID(t, "kate@example.com"), env.accountOwner(t, "idp-kate"))
			})
		})
	}
}
