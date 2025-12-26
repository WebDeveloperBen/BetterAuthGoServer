package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/config"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/token"
)

// mockStoreForMiddleware is a minimal mock store for middleware tests
type mockStoreForMiddleware struct {
	sessions map[string]*models.Session
	users    map[string]*models.User
}

func newMockStoreForMiddleware() *mockStoreForMiddleware {
	return &mockStoreForMiddleware{
		sessions: make(map[string]*models.Session),
		users:    make(map[string]*models.User),
	}
}

func (m *mockStoreForMiddleware) CreateUser(ctx context.Context, user *models.User) error {
	m.users[user.ID] = user
	return nil
}
func (m *mockStoreForMiddleware) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	if user, ok := m.users[id]; ok {
		return user, nil
	}
	return nil, nil
}
func (m *mockStoreForMiddleware) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	return nil, nil
}
func (m *mockStoreForMiddleware) UpdateUser(ctx context.Context, user *models.User) error { return nil }
func (m *mockStoreForMiddleware) DeleteUser(ctx context.Context, id string) error         { return nil }
func (m *mockStoreForMiddleware) SetEmailVerified(ctx context.Context, userID string, v bool) error {
	return nil
}

func (m *mockStoreForMiddleware) CreateSession(ctx context.Context, session *models.Session) error {
	m.sessions[session.TokenHash] = session
	return nil
}

func (m *mockStoreForMiddleware) GetSessionByID(ctx context.Context, id string) (*models.Session, error) {
	for _, s := range m.sessions {
		if s.ID == id {
			return s, nil
		}
	}
	return nil, nil
}

func (m *mockStoreForMiddleware) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*models.Session, error) {
	return m.sessions[tokenHash], nil
}

func (m *mockStoreForMiddleware) ListSessionsByUserID(ctx context.Context, userID string) ([]*models.Session, error) {
	return nil, nil
}

func (m *mockStoreForMiddleware) UpdateSessionLastUsed(ctx context.Context, id string) error {
	return nil
}

func (m *mockStoreForMiddleware) DeleteSession(ctx context.Context, id string) error { return nil }
func (m *mockStoreForMiddleware) DeleteSessionsByUserID(ctx context.Context, userID string) error {
	return nil
}
func (m *mockStoreForMiddleware) DeleteExpiredSessions(ctx context.Context) error { return nil }

func (m *mockStoreForMiddleware) CreateAccount(ctx context.Context, account *models.Account) error {
	return nil
}
func (m *mockStoreForMiddleware) GetAccountByID(ctx context.Context, id string) (*models.Account, error) {
	return nil, nil
}
func (m *mockStoreForMiddleware) GetAccountByUserIDAndProvider(ctx context.Context, userID string, provider models.ProviderType) (*models.Account, error) {
	return nil, nil
}
func (m *mockStoreForMiddleware) GetAccountByProvider(ctx context.Context, provider models.ProviderType, providerAccountID string) (*models.Account, error) {
	return nil, nil
}
func (m *mockStoreForMiddleware) ListAccountsByUserID(ctx context.Context, userID string) ([]*models.Account, error) {
	return nil, nil
}
func (m *mockStoreForMiddleware) UpdateAccount(ctx context.Context, account *models.Account) error {
	return nil
}
func (m *mockStoreForMiddleware) DeleteAccount(ctx context.Context, id string) error { return nil }
func (m *mockStoreForMiddleware) DeleteAccountsByUserID(ctx context.Context, userID string) error {
	return nil
}

func (m *mockStoreForMiddleware) CreateVerification(ctx context.Context, v *models.Verification) error {
	return nil
}
func (m *mockStoreForMiddleware) GetVerificationByTokenHash(ctx context.Context, tokenHash string) (*models.Verification, error) {
	return nil, nil
}
func (m *mockStoreForMiddleware) DeleteVerification(ctx context.Context, id string) error {
	return nil
}
func (m *mockStoreForMiddleware) DeleteVerificationsByUserIDAndType(ctx context.Context, userID string, vType models.VerificationType) error {
	return nil
}
func (m *mockStoreForMiddleware) DeleteExpiredVerifications(ctx context.Context) error { return nil }

func createTestAuth(t *testing.T) (*Auth, *mockStoreForMiddleware) {
	t.Helper()
	store := newMockStoreForMiddleware()

	auth, err := New(store,
		config.WithSecret("test-secret-32-bytes-long-here!!"),
		config.WithBaseURL("http://localhost:3000"),
		config.WithSessionCleanupInterval(0),
		config.WithCSRF(true),
		config.WithTrustedOrigins("http://localhost:3000", "https://example.com"),
	)
	if err != nil {
		t.Fatalf("Failed to create auth: %v", err)
	}

	return auth, store
}

func createValidSession(t *testing.T, auth *Auth, store *mockStoreForMiddleware) (string, *models.Session) {
	t.Helper()

	rawToken, _ := token.Generate()
	tokenHash := auth.tokenHasher.Hash(rawToken)

	// Create a user first
	user := &models.User{
		ID:            "test-user-id",
		Email:         "test@example.com",
		EmailVerified: true,
		Name:          "Test User",
		Role:          "user",
		Banned:        false,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	store.users[user.ID] = user

	session := &models.Session{
		ID:        "test-session-id",
		UserID:    "test-user-id",
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
	}

	store.sessions[tokenHash] = session
	return rawToken, session
}

func TestRequireAuth_ValidSession(t *testing.T) {
	auth, store := createTestAuth(t)
	defer auth.Close()

	rawToken, session := createValidSession(t, auth, store)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check session is in context
		sess := SessionFromContext(r.Context())
		if sess == nil {
			t.Error("Session should be in context")
			return
		}
		if sess.ID != session.ID {
			t.Errorf("Session ID = %s, want %s", sess.ID, session.ID)
		}
		w.WriteHeader(http.StatusOK)
	})

	wrapped := auth.RequireAuth(handler)

	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: rawToken})
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestRequireAuth_NoSession(t *testing.T) {
	auth, _ := createTestAuth(t)
	defer auth.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called")
	})

	wrapped := auth.RequireAuth(handler)

	req := httptest.NewRequest("GET", "/protected", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRequireAuth_InvalidToken(t *testing.T) {
	auth, _ := createTestAuth(t)
	defer auth.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called")
	})

	wrapped := auth.RequireAuth(handler)

	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "invalid-token"})
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRequireAuth_ExpiredSession(t *testing.T) {
	auth, store := createTestAuth(t)
	defer auth.Close()

	rawToken, _ := token.Generate()
	tokenHash := auth.tokenHasher.Hash(rawToken)

	// Create expired session
	session := &models.Session{
		ID:        "expired-session",
		UserID:    "test-user-id",
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
		CreatedAt: time.Now().Add(-2 * time.Hour),
		LastUsed:  time.Now().Add(-1 * time.Hour),
	}
	store.sessions[tokenHash] = session

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called for expired session")
	})

	wrapped := auth.RequireAuth(handler)

	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: rawToken})
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRequireAuth_BearerToken(t *testing.T) {
	auth, store := createTestAuth(t)
	defer auth.Close()

	rawToken, _ := createValidSession(t, auth, store)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if SessionFromContext(r.Context()) == nil {
			t.Error("Session should be in context")
		}
		w.WriteHeader(http.StatusOK)
	})

	wrapped := auth.RequireAuth(handler)

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestOptionalAuth_WithSession(t *testing.T) {
	auth, store := createTestAuth(t)
	defer auth.Close()

	rawToken, session := createValidSession(t, auth, store)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := SessionFromContext(r.Context())
		if sess == nil {
			t.Error("Session should be in context")
			return
		}
		if sess.ID != session.ID {
			t.Errorf("Session ID = %s, want %s", sess.ID, session.ID)
		}
		w.WriteHeader(http.StatusOK)
	})

	wrapped := auth.OptionalAuth(handler)

	req := httptest.NewRequest("GET", "/public", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: rawToken})
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestOptionalAuth_WithoutSession(t *testing.T) {
	auth, _ := createTestAuth(t)
	defer auth.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := SessionFromContext(r.Context())
		if sess != nil {
			t.Error("Session should not be in context")
		}
		w.WriteHeader(http.StatusOK)
	})

	wrapped := auth.OptionalAuth(handler)

	req := httptest.NewRequest("GET", "/public", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// CORS tests are now in the auth/cors package
