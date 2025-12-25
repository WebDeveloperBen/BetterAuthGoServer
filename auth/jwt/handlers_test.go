package jwt

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// Mock implementations for testing
type mockAuthCore struct {
	users    map[string]*plugin.User
	sessions map[string]*plugin.Session
}

func newMockAuthCore() *mockAuthCore {
	return &mockAuthCore{
		users:    make(map[string]*plugin.User),
		sessions: make(map[string]*plugin.Session),
	}
}

func (m *mockAuthCore) GetPluginUser(ctx context.Context, userID string) (*plugin.User, error) {
	return m.users[userID], nil
}

func (m *mockAuthCore) GetPluginUserByEmail(ctx context.Context, email string) (*plugin.User, error) {
	for _, user := range m.users {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, nil
}

func (m *mockAuthCore) CreatePluginUser(ctx context.Context, req plugin.CreateUserRequest) (*plugin.User, error) {
	user := &plugin.User{
		ID:            "user-" + req.Email,
		Email:         req.Email,
		Name:          req.Name,
		EmailVerified: req.EmailVerified,
		Image:         req.Image,
		Role:          "user",
	}
	m.users[user.ID] = user
	return user, nil
}

func (m *mockAuthCore) VerifyPassword(ctx context.Context, userID string, password string) (bool, error) {
	return password == "password", nil
}

func (m *mockAuthCore) CreateSessionForUser(ctx context.Context, userID string, r *http.Request) (*plugin.Session, error) {
	sessionID := "session-" + userID
	session := &plugin.Session{
		ID:     sessionID,
		UserID: userID,
	}
	m.sessions[sessionID] = session
	return session, nil
}

func (m *mockAuthCore) ValidateSessionToken(ctx context.Context, token string) (*plugin.Session, error) {
	return m.sessions[token], nil
}

func (m *mockAuthCore) BaseURL() string {
	return "http://localhost:3000"
}

func (m *mockAuthCore) Secret() string {
	return "test-secret-key-that-is-long-enough-for-jwt!!!"
}

func (m *mockAuthCore) FireOAuthAccountLinked(ctx context.Context, userID, provider, providerAccountID string) error {
	return nil
}

type mockJWTService struct {
	tokens map[string]*TokenPair
}

func newMockJWTService() *mockJWTService {
	return &mockJWTService{
		tokens: make(map[string]*TokenPair),
	}
}

func (m *mockJWTService) GenerateTokenPair(user UserInfo, sessionID string) (*TokenPair, error) {
	tokenID := "token-" + user.ID
	pair := &TokenPair{
		AccessToken:  "access-" + tokenID,
		RefreshToken: "refresh-" + tokenID,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}
	m.tokens[tokenID] = pair
	return pair, nil
}

func (m *mockJWTService) RefreshTokens(ctx context.Context, refreshToken string, user UserInfo) (*TokenPair, error) {
	return m.GenerateTokenPair(user, "refreshed-session")
}

func (m *mockJWTService) ValidateToken(ctx context.Context, tokenString string) (*Claims, error) {
	if len(tokenString) > 6 && tokenString[:6] == "access-" {
		userID := tokenString[7:]
		return &Claims{
			UserID: userID,
		}, nil
	}
	return nil, errInvalidToken
}

func (m *mockJWTService) ValidateRefreshToken(ctx context.Context, tokenString string) (*Claims, error) {
	if len(tokenString) > 8 && tokenString[:8] == "refresh-" {
		userID := tokenString[9:]
		return &Claims{
			UserID: userID,
		}, nil
	}
	return nil, errInvalidToken
}

func (m *mockJWTService) ValidateAccessToken(ctx context.Context, tokenString string) (*Claims, error) {
	return m.ValidateToken(ctx, tokenString)
}

func (m *mockJWTService) RevokeToken(ctx context.Context, tokenString string) error {
	return nil
}

func createTestPlugin(t *testing.T) *Plugin {
	authCore := newMockAuthCore()

	authCore.users["user-123"] = &plugin.User{
		ID:    "user-123",
		Email: "test@example.com",
		Name:  "Test User",
	}

	ctx := plugin.Context{
		BaseURL: "http://localhost:3000",
		Secret:  "test-secret-key-that-is-long-enough-for-jwt-signing-32-chars!!!",
		Auth:    authCore,
	}

	plugin := NewPlugin(
		WithAccessTTL(15*time.Minute),
		WithRefreshTTL(7*24*time.Hour),
	)

	err := plugin.Init(ctx)
	if err != nil {
		t.Fatalf("Failed to initialize plugin: %v", err)
	}

	return plugin
}

func TestTokenHandler_PasswordGrant(t *testing.T) {
	plugin := createTestPlugin(t)
	defer plugin.Close()

	handler := plugin.TokenHandler()

	// Test password grant
	reqBody := tokenRequest{
		GrantType: "password",
		Email:     "test@example.com",
		Password:  "password",
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Response: %s", rec.Code, rec.Body.String())
	}

	var resp tokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if resp.AccessToken == "" || resp.RefreshToken == "" {
		t.Error("Expected access and refresh tokens in response")
	}

	if resp.TokenType != "Bearer" {
		t.Errorf("Expected token type 'Bearer', got %s", resp.TokenType)
	}
}
