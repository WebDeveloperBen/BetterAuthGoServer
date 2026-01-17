package e2e

import (
	"net/http"
	"testing"
)

func TestEmailVerificationFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	for _, dialectEnv := range GetDialects() {
		t.Run(string(dialectEnv.Dialect), func(t *testing.T) {
			env := SetupWithDialect(t, dialectEnv)
			defer env.Cleanup(t)

			t.Run("RequestEmailVerification", func(t *testing.T) {
				env.TruncateTables(t)

				cookies := env.CreateUser(t, "verify@example.com", "password123!", "Verify User")

				resp := env.PostWithCookies(t, "/auth/email/verify/send", nil, cookies)
				defer func() { _ = resp.Body.Close() }()

				if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
					t.Errorf("SendVerificationEmail status = %d, want %d or %d", resp.StatusCode, http.StatusNoContent, http.StatusOK)
				}
			})
		})
	}
}
