package e2e

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/oauth"
)

func TestEmailCaseInsensitivity(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	for _, dialectEnv := range GetDialects() {
		t.Run(string(dialectEnv.Dialect), func(t *testing.T) {
			env := setupOAuth(t, dialectEnv)
			defer env.Cleanup(t)

			t.Run("OAuthEmailDifferingInCaseIsConflict", func(t *testing.T) {
				env.TruncateTables(t)
				env.CreateUser(t, "ada@example.com", "password123!", "Ada")
				env.idp.issue("code-ada", oauth.UserInfo{ID: "idp-ada", Email: " Ada@Example.COM ", EmailVerified: true, Name: "Ada"})

				resp := env.callback(t, "code-ada", env.beginSignIn(t), nil)
				assert.Equal(t, http.StatusConflict, resp.StatusCode)
				assert.Equal(t, oauth.CodeAccountExistsLinkRequired, decodeErrorBody(t, resp)["code"])
				assert.Equal(t, 1, env.count(t, "SELECT COUNT(*) FROM users"))
				assert.Zero(t, env.count(t, "SELECT COUNT(*) FROM oauth_accounts"))
			})

			t.Run("EmailsAreStoredNormalized", func(t *testing.T) {
				env.TruncateTables(t)
				env.CreateUser(t, "Grace@Example.com", "password123!", "Grace")
				assert.Equal(t, 1, env.count(t, "SELECT COUNT(*) FROM users WHERE email = ?", "grace@example.com"))

				// A second sign-up differing only in case is the same address.
				env.CreateUser(t, "GRACE@example.com", "password123!", "Grace 2")
				assert.Equal(t, 1, env.count(t, "SELECT COUNT(*) FROM users"))

				// OAuth with the lower-case address conflicts with the mixed-case sign-up.
				env.idp.issue("code-grace", oauth.UserInfo{ID: "idp-grace", Email: "grace@example.com", EmailVerified: true, Name: "Grace"})
				resp := env.callback(t, "code-grace", env.beginSignIn(t), nil)
				assert.Equal(t, http.StatusConflict, resp.StatusCode)
				_ = resp.Body.Close()

				// Password sign-in matches regardless of case.
				signIn := env.Post(t, "/auth/sign-in", map[string]string{"email": "GRACE@EXAMPLE.COM", "password": "password123!"})
				_ = signIn.Body.Close()
				assert.Equal(t, http.StatusOK, signIn.StatusCode)
			})

			t.Run("NewOAuthUserEmailIsNormalized", func(t *testing.T) {
				env.TruncateTables(t)
				env.signInWithIDP(t, "code-heidi", oauth.UserInfo{ID: "idp-heidi", Email: "Heidi@Example.com", EmailVerified: true, Name: "Heidi"})
				assert.Equal(t, 1, env.count(t, "SELECT COUNT(*) FROM users WHERE email = ?", "heidi@example.com"))
			})
		})
	}
}
