package e2e

import (
	"fmt"
	"net/http"
	"testing"
)

func TestConcurrentSignUps(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	env := Setup(t)
	defer env.Cleanup(t)

	env.TruncateTables(t)

	const numRequests = 10
	results := make(chan int, numRequests)

	for i := range numRequests {
		go func(idx int) {
			body := map[string]string{
				"email":    fmt.Sprintf("concurrent%d@example.com", idx),
				"password": "password123!",
				"name":     fmt.Sprintf("Concurrent User %d", idx),
			}
			resp := env.Post(t, "/auth/sign-up", body)
			results <- resp.StatusCode
			resp.Body.Close()
		}(i)
	}

	successCount := 0
	rateLimitedCount := 0
	for range numRequests {
		status := <-results
		switch status {
		case http.StatusCreated, http.StatusOK:
			successCount++
		case http.StatusTooManyRequests:
			rateLimitedCount++
		}
	}

	if successCount == 0 {
		t.Errorf("ConcurrentSignUps: no requests succeeded (got %d rate limited)", rateLimitedCount)
	}
}

func TestConcurrentSignIns(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	// Use a fresh environment to avoid rate limit conflicts with other tests
	env := Setup(t)
	defer env.Cleanup(t)

	env.TruncateTables(t)

	// Create user and verify it succeeded
	body := map[string]string{
		"email":    "concurrent-signin@example.com",
		"password": "password123!",
		"name":     "Concurrent SignIn User",
	}
	resp := env.Post(t, "/auth/sign-up", body)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to create user for concurrent sign-in test: status %d", resp.StatusCode)
	}
	resp.Body.Close()

	const numRequests = 10
	results := make(chan int, numRequests)

	for range numRequests {
		go func() {
			body := map[string]string{
				"email":    "concurrent-signin@example.com",
				"password": "password123!",
			}
			resp := env.Post(t, "/auth/sign-in", body)
			results <- resp.StatusCode
			resp.Body.Close()
		}()
	}

	successCount := 0
	rateLimitedCount := 0
	otherStatuses := make(map[int]int)
	for range numRequests {
		status := <-results
		switch status {
		case http.StatusOK:
			successCount++
		case http.StatusTooManyRequests:
			rateLimitedCount++
		default:
			otherStatuses[status]++
		}
	}

	if successCount == 0 {
		t.Errorf("ConcurrentSignIns: no requests succeeded (got %d rate limited, other statuses: %v)", rateLimitedCount, otherStatuses)
	}
}
