package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/config"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/token"
)

func TestSessionFromContext_WithSession(t *testing.T) {
	session := &models.Session{
		ID:     "session-123",
		UserID: "user-123",
	}

	ctx := contextWithSession(context.Background(), session)
	result := SessionFromContext(ctx)

	if result == nil {
		t.Fatal("expected session from context")
	}
	if result.ID != "session-123" {
		t.Errorf("session ID = %s, want session-123", result.ID)
	}
}

func TestSessionFromContext_WithoutSession(t *testing.T) {
	ctx := context.Background()
	result := SessionFromContext(ctx)

	if result != nil {
		t.Errorf("expected nil, got session: %v", result)
	}
}

func TestSessionFromContext_WrongType(t *testing.T) {
	// Put a string instead of a session
	ctx := context.WithValue(context.Background(), sessionContextKey, "not a session")
	result := SessionFromContext(ctx)

	if result != nil {
		t.Errorf("expected nil for wrong type, got: %v", result)
	}
}

func TestContextWithSession(t *testing.T) {
	session := &models.Session{
		ID:     "session-456",
		UserID: "user-456",
	}

	ctx := contextWithSession(context.Background(), session)

	// Verify session can be retrieved
	if retrieved, ok := ctx.Value(sessionContextKey).(*models.Session); ok {
		if retrieved.ID != "session-456" {
			t.Errorf("session ID = %s, want session-456", retrieved.ID)
		}
	} else {
		t.Fatal("session not in context")
	}
}

func newAuthForTest(t *testing.T, opts ...config.Option) *Auth {
	t.Helper()

	base := []config.Option{
		config.WithSecret("test-secret-key-32-bytes-long-1234"),
		config.WithBaseURL("http://localhost"),
	}
	base = append(base, opts...)

	a, err := New(newMockSessionStore(), base...)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	return a
}

func TestGetIPAddress_UntrustedHeaders(t *testing.T) {
	a := newAuthForTest(t)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.50")
	req.Header.Set("X-Real-IP", "198.51.100.178")
	req.RemoteAddr = "192.168.1.1:12345"

	ip := a.getIPAddress(req)
	if ip != "192.168.1.1" {
		t.Errorf("IP = %s, want 192.168.1.1 (untrusted proxy headers ignored)", ip)
	}
}

func TestGetIPAddress_TrustedXForwardedFor_Single(t *testing.T) {
	a := newAuthForTest(t, config.WithTrustedProxies("192.168.1.1"))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.50")
	req.RemoteAddr = "192.168.1.1:12345"

	ip := a.getIPAddress(req)
	if ip != "203.0.113.50" {
		t.Errorf("IP = %s, want 203.0.113.50", ip)
	}
}

func TestGetIPAddress_TrustedXForwardedFor_Multiple(t *testing.T) {
	a := newAuthForTest(t, config.WithTrustedProxies("192.168.1.1"))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 70.41.3.18, 150.172.238.178")
	req.RemoteAddr = "192.168.1.1:12345"

	ip := a.getIPAddress(req)
	if ip != "203.0.113.50" {
		t.Errorf("IP = %s, want 203.0.113.50 (first in chain)", ip)
	}
}

func TestGetIPAddress_TrustedXRealIP(t *testing.T) {
	a := newAuthForTest(t, config.WithTrustedProxies("192.168.1.1"))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Real-IP", "198.51.100.178")
	req.RemoteAddr = "192.168.1.1:12345"

	ip := a.getIPAddress(req)
	if ip != "198.51.100.178" {
		t.Errorf("IP = %s, want 198.51.100.178", ip)
	}
}

// mockSessionStore implements Store interface for session tests
type mockSessionStore struct {
	sessions          map[string]*models.Session
	sessionsByToken   map[string]*models.Session
	sessionsByUser    map[string][]*models.Session
	users             map[string]*models.User
	createSessionErr  error
	getSessionErr     error
	deleteSessionErr  error
	updateLastUsedErr error
	deleteExpiredErr  error
}

func newMockSessionStore() *mockSessionStore {
	return &mockSessionStore{
		sessions:        make(map[string]*models.Session),
		sessionsByToken: make(map[string]*models.Session),
		sessionsByUser:  make(map[string][]*models.Session),
		users:           make(map[string]*models.User),
	}
}

func (m *mockSessionStore) CreateSession(ctx context.Context, session *models.Session) error {
	if m.createSessionErr != nil {
		return m.createSessionErr
	}
	m.sessions[session.ID] = session
	m.sessionsByToken[session.TokenHash] = session
	m.sessionsByUser[session.UserID] = append(m.sessionsByUser[session.UserID], session)
	return nil
}

func (m *mockSessionStore) GetSessionByID(ctx context.Context, id string) (*models.Session, error) {
	if m.getSessionErr != nil {
		return nil, m.getSessionErr
	}
	return m.sessions[id], nil
}

func (m *mockSessionStore) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*models.Session, error) {
	if m.getSessionErr != nil {
		return nil, m.getSessionErr
	}
	return m.sessionsByToken[tokenHash], nil
}

func (m *mockSessionStore) ListSessionsByUserID(ctx context.Context, userID string) ([]*models.Session, error) {
	if m.getSessionErr != nil {
		return nil, m.getSessionErr
	}
	return m.sessionsByUser[userID], nil
}

func (m *mockSessionStore) UpdateSessionLastUsed(ctx context.Context, id string) error {
	if m.updateLastUsedErr != nil {
		return m.updateLastUsedErr
	}
	if s, ok := m.sessions[id]; ok {
		s.LastUsed = time.Now()
	}
	return nil
}

func (m *mockSessionStore) DeleteSession(ctx context.Context, id string) error {
	if m.deleteSessionErr != nil {
		return m.deleteSessionErr
	}
	delete(m.sessions, id)
	return nil
}

func (m *mockSessionStore) DeleteSessionsByUserID(ctx context.Context, userID string) error {
	if m.deleteSessionErr != nil {
		return m.deleteSessionErr
	}
	delete(m.sessionsByUser, userID)
	return nil
}

func (m *mockSessionStore) DeleteExpiredSessions(ctx context.Context) error {
	if m.deleteExpiredErr != nil {
		return m.deleteExpiredErr
	}
	now := time.Now()
	for id, s := range m.sessions {
		if s.ExpiresAt.Before(now) {
			delete(m.sessions, id)
		}
	}
	return nil
}

// Implement remaining Store interface methods (minimal stubs)
func (m *mockSessionStore) CreateUser(ctx context.Context, user *models.User) error { return nil }

func (m *mockSessionStore) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	return m.users[id], nil
}

func (m *mockSessionStore) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	return nil, nil
}
func (m *mockSessionStore) UpdateUser(ctx context.Context, user *models.User) error { return nil }
func (m *mockSessionStore) DeleteUser(ctx context.Context, id string) error         { return nil }
func (m *mockSessionStore) SetEmailVerified(ctx context.Context, userID string, verified bool) error {
	return nil
}

func (m *mockSessionStore) CreateAccount(ctx context.Context, account *models.Account) error {
	return nil
}

func (m *mockSessionStore) GetAccountByID(ctx context.Context, id string) (*models.Account, error) {
	return nil, nil
}

func (m *mockSessionStore) GetAccountByProvider(ctx context.Context, provider models.ProviderType, providerAccountID string) (*models.Account, error) {
	return nil, nil
}

func (m *mockSessionStore) GetAccountByUserIDAndProvider(ctx context.Context, userID string, provider models.ProviderType) (*models.Account, error) {
	return nil, nil
}

func (m *mockSessionStore) ListAccountsByUserID(ctx context.Context, userID string) ([]*models.Account, error) {
	return nil, nil
}

func (m *mockSessionStore) UpdateAccount(ctx context.Context, account *models.Account) error {
	return nil
}
func (m *mockSessionStore) DeleteAccount(ctx context.Context, id string) error { return nil }
func (m *mockSessionStore) DeleteAccountsByUserID(ctx context.Context, userID string) error {
	return nil
}

func (m *mockSessionStore) CreateVerification(ctx context.Context, v *models.Verification) error {
	return nil
}

func (m *mockSessionStore) GetVerificationByTokenHash(ctx context.Context, tokenHash string) (*models.Verification, error) {
	return nil, nil
}
func (m *mockSessionStore) DeleteVerification(ctx context.Context, id string) error { return nil }
func (m *mockSessionStore) DeleteExpiredVerifications(ctx context.Context) error    { return nil }
func (m *mockSessionStore) DeleteVerificationsByUserIDAndType(ctx context.Context, userID string, vType models.VerificationType) error {
	return nil
}

func (m *mockSessionStore) Migrate(ctx context.Context) error { return nil }

func TestValidateSession_Valid(t *testing.T) {
	store := newMockSessionStore()
	hasher := token.NewHasher("test-secret-32-bytes-minimum!!!")

	rawToken := "test-raw-token"
	tokenHash := hasher.Hash(rawToken)

	session := &models.Session{
		ID:        "session-123",
		UserID:    "user-123",
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		LastUsed:  time.Now(),
	}
	store.sessions[session.ID] = session
	store.sessionsByToken[tokenHash] = session

	auth := &Auth{
		store:       store,
		tokenHasher: hasher,
	}

	result, err := auth.ValidateSession(context.Background(), rawToken)
	if err != nil {
		t.Fatalf("ValidateSession failed: %v", err)
	}
	if result.ID != "session-123" {
		t.Errorf("session ID = %s, want session-123", result.ID)
	}
}

func TestValidateSession_NotFound(t *testing.T) {
	store := newMockSessionStore()
	hasher := token.NewHasher("test-secret-32-bytes-minimum!!!")

	auth := &Auth{
		store:       store,
		tokenHasher: hasher,
	}

	_, err := auth.ValidateSession(context.Background(), "non-existent-token")
	if !errors.Is(err, models.ErrSessionNotFound) {
		t.Errorf("error = %v, want ErrSessionNotFound", err)
	}
}

func TestValidateSession_Expired(t *testing.T) {
	store := newMockSessionStore()
	hasher := token.NewHasher("test-secret-32-bytes-minimum!!!")

	rawToken := "test-raw-token"
	tokenHash := hasher.Hash(rawToken)

	session := &models.Session{
		ID:        "session-123",
		UserID:    "user-123",
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
		LastUsed:  time.Now(),
	}
	store.sessions[session.ID] = session
	store.sessionsByToken[tokenHash] = session

	auth := &Auth{
		store:       store,
		tokenHasher: hasher,
	}

	_, err := auth.ValidateSession(context.Background(), rawToken)
	if !errors.Is(err, models.ErrSessionExpired) {
		t.Errorf("error = %v, want ErrSessionExpired", err)
	}
}

func TestValidateSession_StoreError(t *testing.T) {
	store := newMockSessionStore()
	store.getSessionErr = errors.New("database error")
	hasher := token.NewHasher("test-secret-32-bytes-minimum!!!")

	auth := &Auth{
		store:       store,
		tokenHasher: hasher,
	}

	_, err := auth.ValidateSession(context.Background(), "any-token")
	if err == nil {
		t.Error("expected error from store")
	}
}

func TestResolveSession(t *testing.T) {
	auth := newAuthForTest(t)
	defer auth.Close()
	store := auth.store.(*mockSessionStore)

	rawToken := "resolve-session-token"
	session := &models.Session{
		ID: "session-id", UserID: "user-id",
		TokenHash: auth.tokenHasher.Hash(rawToken),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	store.sessions[session.ID] = session
	store.sessionsByToken[session.TokenHash] = session
	store.users[session.UserID] = &models.User{ID: session.UserID, Email: "user@example.com"}

	t.Run("cookie", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(&http.Cookie{Name: auth.config.SessionCookie, Value: rawToken})
		resolved, err := auth.ResolveSession(request)
		if err != nil {
			t.Fatal(err)
		}
		if resolved.Session.ID != session.ID || resolved.User.ID != session.UserID || !resolved.CookieAuthenticated {
			t.Fatalf("unexpected resolved identity: %#v", resolved)
		}
	})

	t.Run("bearer", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.Header.Set("Authorization", "Bearer "+rawToken)
		resolved, err := auth.ResolveSession(request)
		if err != nil {
			t.Fatal(err)
		}
		if resolved.CookieAuthenticated {
			t.Fatal("bearer authentication reported as cookie-authenticated")
		}
	})

	t.Run("banned user", func(t *testing.T) {
		store.users[session.UserID].Banned = true
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(&http.Cookie{Name: auth.config.SessionCookie, Value: rawToken})
		_, err := auth.ResolveSession(request)
		if !errors.Is(err, models.ErrUserBanned) {
			t.Fatalf("error = %v, want ErrUserBanned", err)
		}
	})
}

func TestListSessions_Active(t *testing.T) {
	store := newMockSessionStore()

	// Create sessions - some expired, some active
	now := time.Now()
	store.sessionsByUser["user-123"] = []*models.Session{
		{ID: "session-1", UserID: "user-123", ExpiresAt: now.Add(24 * time.Hour)},
		{ID: "session-2", UserID: "user-123", ExpiresAt: now.Add(-1 * time.Hour)}, // Expired
		{ID: "session-3", UserID: "user-123", ExpiresAt: now.Add(48 * time.Hour)},
	}
	store.sessions["session-1"] = store.sessionsByUser["user-123"][0]
	store.sessions["session-2"] = store.sessionsByUser["user-123"][1]
	store.sessions["session-3"] = store.sessionsByUser["user-123"][2]

	auth := &Auth{store: store}

	sessions, err := auth.ListSessions(context.Background(), "user-123")
	if err != nil {
		t.Fatalf("ListSessions failed: %v", err)
	}

	// Should return only 2 active sessions
	if len(sessions) != 2 {
		t.Errorf("got %d sessions, want 2 active", len(sessions))
	}
}

func TestListSessions_NoSessions(t *testing.T) {
	store := newMockSessionStore()
	auth := &Auth{store: store}

	sessions, err := auth.ListSessions(context.Background(), "user-without-sessions")
	if err != nil {
		t.Fatalf("ListSessions failed: %v", err)
	}

	if len(sessions) != 0 {
		t.Errorf("got %d sessions, want 0", len(sessions))
	}
}

func TestRevokeSession(t *testing.T) {
	store := newMockSessionStore()
	store.sessions["session-123"] = &models.Session{ID: "session-123"}

	auth := &Auth{store: store}

	err := auth.RevokeSession(context.Background(), "session-123")
	if err != nil {
		t.Fatalf("RevokeSession failed: %v", err)
	}

	// Session should be deleted
	if _, exists := store.sessions["session-123"]; exists {
		t.Error("session should be deleted")
	}
}

func TestRevokeSession_Error(t *testing.T) {
	store := newMockSessionStore()
	store.deleteSessionErr = errors.New("delete failed")

	auth := &Auth{store: store}

	err := auth.RevokeSession(context.Background(), "session-123")
	if err == nil {
		t.Error("expected error")
	}
}

func TestRevokeAllSessions(t *testing.T) {
	store := newMockSessionStore()
	store.sessionsByUser["user-123"] = []*models.Session{
		{ID: "session-1"},
		{ID: "session-2"},
	}

	auth := &Auth{store: store}

	err := auth.RevokeAllSessions(context.Background(), "user-123")
	if err != nil {
		t.Fatalf("RevokeAllSessions failed: %v", err)
	}

	// User sessions should be deleted
	if len(store.sessionsByUser["user-123"]) != 0 {
		t.Error("user sessions should be deleted")
	}
}

func TestRefreshSession_Valid(t *testing.T) {
	store := newMockSessionStore()
	originalTime := time.Now().Add(-1 * time.Hour)
	session := &models.Session{
		ID:       "session-123",
		LastUsed: originalTime,
	}
	store.sessions["session-123"] = session

	auth := &Auth{store: store}

	result, err := auth.RefreshSession(context.Background(), "session-123")
	if err != nil {
		t.Fatalf("RefreshSession failed: %v", err)
	}

	// LastUsed should be updated
	if !result.LastUsed.After(originalTime) {
		t.Error("LastUsed should be updated to now")
	}
}

func TestRefreshSession_NotFound(t *testing.T) {
	store := newMockSessionStore()
	auth := &Auth{store: store}

	_, err := auth.RefreshSession(context.Background(), "non-existent")
	if !errors.Is(err, models.ErrSessionNotFound) {
		t.Errorf("error = %v, want ErrSessionNotFound", err)
	}
}

func TestCleanupExpiredSessions(t *testing.T) {
	store := newMockSessionStore()
	now := time.Now()

	store.sessions["active"] = &models.Session{ID: "active", ExpiresAt: now.Add(24 * time.Hour)}
	store.sessions["expired1"] = &models.Session{ID: "expired1", ExpiresAt: now.Add(-1 * time.Hour)}
	store.sessions["expired2"] = &models.Session{ID: "expired2", ExpiresAt: now.Add(-2 * time.Hour)}

	auth := &Auth{store: store}

	err := auth.CleanupExpiredSessions(context.Background())
	if err != nil {
		t.Fatalf("CleanupExpiredSessions failed: %v", err)
	}

	// Only active session should remain
	if len(store.sessions) != 1 {
		t.Errorf("got %d sessions, want 1 active", len(store.sessions))
	}
	if _, exists := store.sessions["active"]; !exists {
		t.Error("active session should still exist")
	}
}

func TestCleanupExpiredSessions_Error(t *testing.T) {
	store := newMockSessionStore()
	store.deleteExpiredErr = errors.New("cleanup failed")

	auth := &Auth{store: store}

	err := auth.CleanupExpiredSessions(context.Background())
	if err == nil {
		t.Error("expected error")
	}
}

func TestCreateSession(t *testing.T) {
	store := newMockSessionStore()
	hasher := token.NewHasher("test-secret-32-bytes-minimum!!!")

	auth := &Auth{
		store:       store,
		tokenHasher: hasher,
		config: &config.Config{
			SessionDuration: 24 * time.Hour,
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "TestBrowser/1.0")
	req.RemoteAddr = "192.168.1.1:12345"

	session, err := auth.createSession(context.Background(), "user-123", req)
	if err != nil {
		t.Fatalf("createSession failed: %v", err)
	}

	if session.ID == "" {
		t.Error("session ID should be set")
	}
	if session.UserID != "user-123" {
		t.Errorf("UserID = %s, want user-123", session.UserID)
	}
	if session.TokenHash == "" {
		t.Error("TokenHash should be set")
	}
	if session.RawToken == "" {
		t.Error("RawToken should be set")
	}
	if session.IPAddress == nil || *session.IPAddress != "192.168.1.1" {
		t.Error("IPAddress should be set from request")
	}
	if session.UserAgent == nil || *session.UserAgent != "TestBrowser/1.0" {
		t.Error("UserAgent should be set from request")
	}

	// Session should be in store
	if _, exists := store.sessions[session.ID]; !exists {
		t.Error("session should be stored")
	}
}

func TestCreateSession_NilRequest(t *testing.T) {
	store := newMockSessionStore()
	hasher := token.NewHasher("test-secret-32-bytes-minimum!!!")

	auth := &Auth{
		store:       store,
		tokenHasher: hasher,
		config: &config.Config{
			SessionDuration: 24 * time.Hour,
		},
	}

	session, err := auth.createSession(context.Background(), "user-123", nil)
	if err != nil {
		t.Fatalf("createSession failed: %v", err)
	}

	// IP and User-Agent should be nil when request is nil
	if session.IPAddress != nil {
		t.Error("IPAddress should be nil when request is nil")
	}
	if session.UserAgent != nil {
		t.Error("UserAgent should be nil when request is nil")
	}
}

func TestCreateSession_LongUserAgent(t *testing.T) {
	store := newMockSessionStore()
	hasher := token.NewHasher("test-secret-32-bytes-minimum!!!")

	auth := &Auth{
		store:       store,
		tokenHasher: hasher,
		config: &config.Config{
			SessionDuration: 24 * time.Hour,
		},
	}

	// Create a very long user agent (>500 chars)
	var longUA strings.Builder
	for range 600 {
		longUA.WriteString("x")
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", longUA.String())

	session, err := auth.createSession(context.Background(), "user-123", req)
	if err != nil {
		t.Fatalf("createSession failed: %v", err)
	}

	// User agent should be truncated to 500 chars
	if session.UserAgent == nil {
		t.Fatal("UserAgent should not be nil")
	}
	if len(*session.UserAgent) != 500 {
		t.Errorf("UserAgent length = %d, want 500 (truncated)", len(*session.UserAgent))
	}
}

func TestCreateSession_StoreError(t *testing.T) {
	store := newMockSessionStore()
	store.createSessionErr = errors.New("store error")
	hasher := token.NewHasher("test-secret-32-bytes-minimum!!!")

	auth := &Auth{
		store:       store,
		tokenHasher: hasher,
		config: &config.Config{
			SessionDuration: 24 * time.Hour,
		},
	}

	_, err := auth.createSession(context.Background(), "user-123", nil)
	if err == nil {
		t.Error("expected error from store")
	}
}
