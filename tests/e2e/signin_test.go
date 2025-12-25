package e2e

import (
	"net/http"
	"testing"
)

func TestSignInFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	env := Setup(t)
	defer env.Cleanup(t)

	t.Run("SuccessfulSignIn", func(t *testing.T) {
		env.TruncateTables(t)
		env.CreateUser(t, "signin@example.com", "password123!", "Sign In User")

		body := map[string]string{
			"email":    "signin@example.com",
			"password": "password123!",
		}

		resp := env.Post(t, "/auth/sign-in", body)
		cookies := resp.Cookies()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("SignIn status = %d, want %d", resp.StatusCode, http.StatusOK)
		}

		var result map[string]any
		DecodeResponse(t, resp, &result)

		if result["user"] == nil {
			t.Error("Response missing user object")
		}
		if result["session"] == nil {
			t.Error("Response missing session object")
		}

		var sessionCookie *http.Cookie
		for _, c := range cookies {
			if c.Name == "session" {
				sessionCookie = c
				break
			}
		}
		if sessionCookie == nil {
			t.Error("Response missing session cookie")
		} else if !sessionCookie.HttpOnly {
			t.Error("Session cookie should be HttpOnly")
		}
	})

	t.Run("SignInWithWrongPassword", func(t *testing.T) {
		env.TruncateTables(t)
		env.CreateUser(t, "wrongpw@example.com", "correctPassword!", "Wrong PW User")

		body := map[string]string{
			"email":    "wrongpw@example.com",
			"password": "wrongPassword!",
		}

		resp := env.Post(t, "/auth/sign-in", body)
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Wrong password SignIn status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
		}
	})

	t.Run("SignInWithNonExistentUser", func(t *testing.T) {
		env.TruncateTables(t)

		body := map[string]string{
			"email":    "nonexistent@example.com",
			"password": "anypassword!",
		}

		resp := env.Post(t, "/auth/sign-in", body)
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Non-existent user SignIn status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
		}
	})
}
