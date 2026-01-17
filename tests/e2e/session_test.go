package e2e

import (
	"net/http"
	"testing"
)

func TestSessionFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	for _, dialectEnv := range GetDialects() {
		t.Run(string(dialectEnv.Dialect), func(t *testing.T) {
			env := SetupWithDialect(t, dialectEnv)
			defer env.Cleanup(t)

			t.Run("GetSessionWithValidCookie", func(t *testing.T) {
				env.TruncateTables(t)

				cookies := env.CreateUser(t, "session@example.com", "password123!", "Session User")

				resp := env.Get(t, "/auth/me", cookies)
				defer func() { _ = resp.Body.Close() }()

				if resp.StatusCode != http.StatusOK {
					t.Errorf("GetMe status = %d, want %d", resp.StatusCode, http.StatusOK)
				}

				var result map[string]any
				DecodeResponse(t, resp, &result)

				if result["user"] == nil {
					t.Error("Response missing user object")
				}
			})

			t.Run("GetSessionWithoutCookie", func(t *testing.T) {
				env.TruncateTables(t)

				resp := env.Get(t, "/auth/me", nil)
				defer func() { _ = resp.Body.Close() }()

				if resp.StatusCode != http.StatusUnauthorized {
					t.Errorf("GetMe without cookie status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
				}
			})

			t.Run("ListSessions", func(t *testing.T) {
				env.TruncateTables(t)

				env.CreateUser(t, "listsessions@example.com", "password123!", "List Sessions User")

				signInBody := map[string]string{
					"email":    "listsessions@example.com",
					"password": "password123!",
				}
				for i := 0; i < 3; i++ {
					resp := env.Post(t, "/auth/sign-in", signInBody)
					_ = resp.Body.Close()
				}

				resp := env.Post(t, "/auth/sign-in", signInBody)
				cookies := resp.Cookies()
				_ = resp.Body.Close()

				resp = env.Get(t, "/auth/sessions", cookies)
				defer func() { _ = resp.Body.Close() }()

				if resp.StatusCode != http.StatusOK {
					t.Errorf("ListSessions status = %d, want %d", resp.StatusCode, http.StatusOK)
				}

				var result map[string]any
				DecodeResponse(t, resp, &result)

				sessions, ok := result["sessions"].([]any)
				if !ok {
					t.Fatal("Response missing sessions array")
				}

				if len(sessions) < 4 {
					t.Errorf("Expected at least 4 sessions, got %d", len(sessions))
				}
			})
		})
	}
}
