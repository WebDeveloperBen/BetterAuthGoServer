package e2e

import (
	"net/http"
	"testing"
)

func TestSignOutFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	for _, dialectEnv := range GetDialects() {
		t.Run(string(dialectEnv.Dialect), func(t *testing.T) {
			env := SetupWithDialect(t, dialectEnv)
			defer env.Cleanup(t)

			t.Run("SignOut", func(t *testing.T) {
				env.TruncateTables(t)

				cookies := env.CreateUser(t, "signout@example.com", "password123!", "Sign Out User")

				resp := env.PostWithCookies(t, "/auth/sign-out", nil, cookies)
				defer func() { _ = resp.Body.Close() }()

				if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
					t.Errorf("SignOut status = %d, want %d or %d", resp.StatusCode, http.StatusNoContent, http.StatusOK)
				}

				for _, c := range resp.Cookies() {
					if c.Name == "session" {
						if c.MaxAge > 0 {
							t.Error("Session cookie should be expired after sign-out")
						}
						break
					}
				}

				resp = env.Get(t, "/auth/me", cookies)
				defer func() { _ = resp.Body.Close() }()

				if resp.StatusCode != http.StatusUnauthorized {
					t.Errorf("GetMe after SignOut status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
				}
			})
		})
	}
}
