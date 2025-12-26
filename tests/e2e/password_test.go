package e2e

import (
	"net/http"
	"testing"
)

func TestPasswordResetFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	env := Setup(t)
	defer env.Cleanup(t)

	t.Run("RequestPasswordReset", func(t *testing.T) {
		env.TruncateTables(t)

		env.CreateUser(t, "reset@example.com", "oldpassword123!", "Reset User")

		resetBody := map[string]string{
			"email": "reset@example.com",
		}
		resp := env.Post(t, "/auth/password/reset", resetBody)
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
			t.Errorf("PasswordReset status = %d, want %d or %d", resp.StatusCode, http.StatusNoContent, http.StatusOK)
		}
	})

	t.Run("RequestPasswordResetNonExistentUser", func(t *testing.T) {
		env.TruncateTables(t)

		resetBody := map[string]string{
			"email": "nonexistent@example.com",
		}
		resp := env.Post(t, "/auth/password/reset", resetBody)
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
			t.Errorf("PasswordReset for non-existent user status = %d, want %d or %d", resp.StatusCode, http.StatusNoContent, http.StatusOK)
		}
	})
}

func TestPasswordChangeFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	env := Setup(t)
	defer env.Cleanup(t)

	t.Run("SuccessfulPasswordChange", func(t *testing.T) {
		env.TruncateTables(t)

		cookies := env.CreateUser(t, "changepw@example.com", "oldpassword123!", "Change PW User")

		changeBody := map[string]string{
			"old_password": "oldpassword123!",
			"new_password": "newpassword456!",
		}
		resp := env.PostWithCookies(t, "/auth/password/change", changeBody, cookies)
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
			t.Errorf("PasswordChange status = %d, want %d or %d", resp.StatusCode, http.StatusNoContent, http.StatusOK)
		}

		resp = env.Get(t, "/auth/me", cookies)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Error("Old session should be invalidated after password change")
		}

		signInBody := map[string]string{
			"email":    "changepw@example.com",
			"password": "newpassword456!",
		}
		resp = env.Post(t, "/auth/sign-in", signInBody)
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("SignIn with new password status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
	})

	t.Run("PasswordChangeWithWrongOldPassword", func(t *testing.T) {
		env.TruncateTables(t)

		cookies := env.CreateUser(t, "wrongold@example.com", "correctOldPassword!", "Wrong Old PW User")

		changeBody := map[string]string{
			"old_password": "wrongOldPassword!",
			"new_password": "newpassword456!",
		}
		resp := env.PostWithCookies(t, "/auth/password/change", changeBody, cookies)
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("PasswordChange with wrong old password status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
		}
	})
}
