package e2e

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
)

func TestRateLimitingApplied(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	// Use rate limiting setup with limit of 10 requests/minute
	env := SetupWithRateLimiting(t, 10)
	defer env.Cleanup(t)

	t.Run("SignInRateLimited", func(t *testing.T) {
		env.TruncateTables(t)

		env.CreateUser(t, "ratelimit@example.com", "password123!", "Rate Limit User")

		rateLimitedCount := 0
		for i := 0; i < 20; i++ {
			body := map[string]string{
				"email":    "ratelimit@example.com",
				"password": "wrongpassword",
			}
			resp := env.Post(t, "/auth/sign-in", body)
			if resp.StatusCode == http.StatusTooManyRequests {
				rateLimitedCount++
			}
			resp.Body.Close()
		}

		if rateLimitedCount == 0 {
			t.Error("Expected rate limiting to be applied after multiple failed sign-in attempts, but no 429 responses received")
		}
	})

	t.Run("SignUpRateLimited", func(t *testing.T) {
		env.TruncateTables(t)

		rateLimitedCount := 0
		for i := 0; i < 20; i++ {
			body := map[string]string{
				"email":    fmt.Sprintf("ratelimit%d@example.com", i),
				"password": "password123!",
				"name":     fmt.Sprintf("User %d", i),
			}
			resp := env.Post(t, "/auth/sign-up", body)
			if resp.StatusCode == http.StatusTooManyRequests {
				rateLimitedCount++
			}
			resp.Body.Close()
		}

		if rateLimitedCount == 0 {
			t.Error("Expected rate limiting to be applied after multiple sign-up attempts, but no 429 responses received")
		}
	})
}

func TestIPSpoofingPrevention(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	// Use rate limiting setup with limit of 10 requests/minute
	env := SetupWithRateLimiting(t, 10)
	defer env.Cleanup(t)

	t.Run("UntrustedXForwardedForIgnored", func(t *testing.T) {
		env.TruncateTables(t)
		env.CreateUser(t, "spoof@example.com", "password123!", "Spoof User")

		rateLimitedCount := 0
		for i := 0; i < 20; i++ {
			body := map[string]string{
				"email":    "spoof@example.com",
				"password": "wrongpassword",
			}
			resp := env.PostWithHeaders(t, "/auth/sign-in", body, map[string]string{
				"X-Forwarded-For": fmt.Sprintf("10.0.0.%d", i),
			})
			if resp.StatusCode == http.StatusTooManyRequests {
				rateLimitedCount++
			}
			resp.Body.Close()
		}

		if rateLimitedCount == 0 {
			t.Error("Rate limiting was bypassed via X-Forwarded-For spoofing - untrusted proxy headers should be ignored")
		}
	})
}

func TestEmailValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	env := Setup(t)
	defer env.Cleanup(t)

	invalidEmails := []string{
		"notanemail",
		"missing@domain",
		"@nodomain.com",
		"spaces in@email.com",
		"",
		"   ",
		"<script>alert(1)</script>@test.com",
	}

	for _, email := range invalidEmails {
		t.Run(fmt.Sprintf("RejectInvalidEmail_%s", email), func(t *testing.T) {
			env.TruncateTables(t)

			body := map[string]string{
				"email":    email,
				"password": "password123!",
				"name":     "Test User",
			}
			resp := env.Post(t, "/auth/sign-up", body)
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("Invalid email '%s' was accepted with status %d, want %d",
					email, resp.StatusCode, http.StatusBadRequest)
			}
		})
	}
}

func TestAccountLockout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	env := Setup(t)
	defer env.Cleanup(t)

	t.Run("LockoutAfterFailedAttempts", func(t *testing.T) {
		env.TruncateTables(t)
		env.CreateUser(t, "lockout@example.com", "correctpassword!", "Lockout User")

		for i := 0; i < 10; i++ {
			body := map[string]string{
				"email":    "lockout@example.com",
				"password": "wrongpassword",
			}
			resp := env.Post(t, "/auth/sign-in", body)
			resp.Body.Close()
		}

		body := map[string]string{
			"email":    "lockout@example.com",
			"password": "correctpassword!",
		}
		resp := env.Post(t, "/auth/sign-in", body)
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("Account was not locked after multiple failed login attempts - successful login was still allowed")
		}
	})
}

func TestInputSanitization(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	env := Setup(t)
	defer env.Cleanup(t)

	t.Run("XSSInNamePrevented", func(t *testing.T) {
		env.TruncateTables(t)

		xssPayloads := []string{
			"<script>alert('xss')</script>",
			"<img src=x onerror=alert(1)>",
			"javascript:alert(1)",
			"<svg onload=alert(1)>",
		}

		for _, payload := range xssPayloads {
			body := map[string]string{
				"email":    "xss@example.com",
				"password": "password123!",
				"name":     payload,
			}
			resp := env.Post(t, "/auth/sign-up", body)

			if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
				var result map[string]any
				DecodeResponse(t, resp, &result)

				if user, ok := result["user"].(map[string]any); ok {
					name := user["name"].(string)
					if strings.Contains(name, "<") || strings.Contains(name, ">") {
						t.Errorf("XSS payload was not sanitized (contains < or >): %s", name)
					}
				}
			}
			resp.Body.Close()
			env.TruncateTables(t)
		}
	})
}

func TestSessionCookieSecurity(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	env := Setup(t)
	defer env.Cleanup(t)

	t.Run("SessionCookieHasStrictSameSite", func(t *testing.T) {
		env.TruncateTables(t)

		body := map[string]string{
			"email":    "cookie@example.com",
			"password": "password123!",
			"name":     "Cookie User",
		}
		resp := env.Post(t, "/auth/sign-up", body)
		defer resp.Body.Close()

		for _, cookie := range resp.Cookies() {
			if cookie.Name == "session" {
				if cookie.SameSite != http.SameSiteStrictMode {
					t.Errorf("Session cookie SameSite = %v, want SameSiteStrictMode", cookie.SameSite)
				}
				break
			}
		}
	})
}

func TestMaxSessionsPerUser(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	env := Setup(t)
	defer env.Cleanup(t)

	t.Run("LimitSessionsPerUser", func(t *testing.T) {
		env.TruncateTables(t)
		env.CreateUser(t, "sessions@example.com", "password123!", "Sessions User")

		maxAllowed := 10
		for i := 0; i < maxAllowed+5; i++ {
			body := map[string]string{
				"email":    "sessions@example.com",
				"password": "password123!",
			}
			resp := env.Post(t, "/auth/sign-in", body)
			resp.Body.Close()
		}

		body := map[string]string{
			"email":    "sessions@example.com",
			"password": "password123!",
		}
		resp := env.Post(t, "/auth/sign-in", body)
		cookies := resp.Cookies()
		resp.Body.Close()

		resp = env.Get(t, "/auth/sessions", cookies)
		defer resp.Body.Close()

		var result map[string]any
		DecodeResponse(t, resp, &result)

		if sessions, ok := result["sessions"].([]any); ok {
			if len(sessions) > maxAllowed {
				t.Errorf("User has %d sessions, but max should be %d", len(sessions), maxAllowed)
			}
		}
	})
}

func TestSecurityHeaders(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	env := Setup(t)
	defer env.Cleanup(t)

	t.Run("SecurityHeadersPresent", func(t *testing.T) {
		resp := env.Get(t, "/auth/me", nil)
		defer resp.Body.Close()

		requiredHeaders := map[string]string{
			"X-Content-Type-Options": "nosniff",
			"X-Frame-Options":        "DENY",
		}

		for header, expectedValue := range requiredHeaders {
			value := resp.Header.Get(header)
			if value == "" {
				t.Errorf("Missing security header: %s", header)
			} else if value != expectedValue {
				t.Errorf("Header %s = %s, want %s", header, value, expectedValue)
			}
		}
	})
}

func TestConcurrentRateLimiting(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	// Use rate limiting setup with limit of 10 requests/minute
	env := SetupWithRateLimiting(t, 10)
	defer env.Cleanup(t)

	t.Run("ConcurrentRequestsRateLimited", func(t *testing.T) {
		env.TruncateTables(t)
		env.CreateUser(t, "concurrent@example.com", "password123!", "Concurrent User")

		var wg sync.WaitGroup
		results := make(chan int, 50)

		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				body := map[string]string{
					"email":    "concurrent@example.com",
					"password": "wrongpassword",
				}
				resp := env.Post(t, "/auth/sign-in", body)
				results <- resp.StatusCode
				resp.Body.Close()
			}()
		}

		wg.Wait()
		close(results)

		rateLimitedCount := 0
		for status := range results {
			if status == http.StatusTooManyRequests {
				rateLimitedCount++
			}
		}

		if rateLimitedCount == 0 {
			t.Error("No requests were rate limited during concurrent access")
		}
	})
}
