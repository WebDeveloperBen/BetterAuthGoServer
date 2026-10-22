package e2e

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/oauth"
)

func TestOAuthSignInRefusesBannedUser(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	for _, dialectEnv := range GetDialects() {
		t.Run(string(dialectEnv.Dialect), func(t *testing.T) {
			env := setupOAuth(t, dialectEnv)
			defer env.Cleanup(t)
			env.TruncateTables(t)

			env.signInWithIDP(t, "code-ivan", oauth.UserInfo{ID: "idp-ivan", Email: "ivan@example.com", EmailVerified: true, Name: "Ivan"})
			ivanID := env.userID(t, "ivan@example.com")
			_, err := env.DB.ExecContext(context.Background(), rebind(env.Dialect, "UPDATE users SET banned = ? WHERE id = ?"), true, ivanID)
			require.NoError(t, err)
			sessionsBefore := env.count(t, "SELECT COUNT(*) FROM sessions WHERE user_id = ?", ivanID)

			env.idp.issue("code-ivan-again", oauth.UserInfo{ID: "idp-ivan", Email: "ivan@example.com", EmailVerified: true, Name: "Ivan"})
			resp := env.callback(t, "code-ivan-again", env.beginSignIn(t), nil)
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
			assert.Nil(t, GetSessionCookie(resp))
			assert.Equal(t, oauth.CodeUserBanned, decodeErrorBody(t, resp)["code"])
			assert.Equal(t, sessionsBefore, env.count(t, "SELECT COUNT(*) FROM sessions WHERE user_id = ?", ivanID))
		})
	}
}
