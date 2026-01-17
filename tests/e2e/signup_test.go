package e2e

import (
	"net/http"
	"testing"
)

func TestSignUpFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	for _, dialectEnv := range GetDialects() {
		t.Run(string(dialectEnv.Dialect), func(t *testing.T) {
			env := SetupWithDialect(t, dialectEnv)
			defer env.Cleanup(t)

			t.Run("SuccessfulSignUp", func(t *testing.T) {
				env.TruncateTables(t)

				body := map[string]string{
					"email":    "newuser@example.com",
					"password": "securePassword123!",
					"name":     "New User",
				}

				resp := env.Post(t, "/auth/sign-up", body)
				cookies := resp.Cookies()

				if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
					t.Errorf("SignUp status = %d, want %d or %d", resp.StatusCode, http.StatusCreated, http.StatusOK)
				}

				var result map[string]any
				DecodeResponse(t, resp, &result)

				user, ok := result["user"].(map[string]any)
				if !ok {
					t.Fatal("Response missing user object")
				}

				if user["email"] != "newuser@example.com" {
					t.Errorf("user.email = %v, want newuser@example.com", user["email"])
				}

				if user["name"] != "New User" {
					t.Errorf("user.name = %v, want New User", user["name"])
				}

				var hasSessionCookie bool
				for _, c := range cookies {
					if c.Name == "session" {
						hasSessionCookie = true
						break
					}
				}
				if !hasSessionCookie {
					t.Error("Response missing session cookie")
				}
			})

			t.Run("SignUpWithExistingEmail", func(t *testing.T) {
				env.TruncateTables(t)

				body := map[string]string{
					"email":    "existing@example.com",
					"password": "password123!",
					"name":     "First User",
				}

				resp := env.Post(t, "/auth/sign-up", body)
				_ = resp.Body.Close()

				resp = env.Post(t, "/auth/sign-up", body)
				defer func() { _ = resp.Body.Close() }()

				if resp.StatusCode != http.StatusConflict {
					t.Errorf("Duplicate SignUp status = %d, want %d", resp.StatusCode, http.StatusConflict)
				}
			})

			t.Run("SignUpWithWeakPassword", func(t *testing.T) {
				env.TruncateTables(t)

				body := map[string]string{
					"email":    "weak@example.com",
					"password": "123",
					"name":     "Weak Password User",
				}

				resp := env.Post(t, "/auth/sign-up", body)
				defer func() { _ = resp.Body.Close() }()

				if resp.StatusCode != http.StatusBadRequest {
					t.Errorf("Weak password SignUp status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
				}
			})

			t.Run("SignUpWithMissingFields", func(t *testing.T) {
				env.TruncateTables(t)

				body := map[string]string{
					"email": "incomplete@example.com",
				}

				resp := env.Post(t, "/auth/sign-up", body)
				defer func() { _ = resp.Body.Close() }()

				if resp.StatusCode != http.StatusBadRequest {
					t.Errorf("Incomplete SignUp status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
				}
			})
		})
	}
}
