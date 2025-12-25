package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
)

func TestToUserResponse(t *testing.T) {
	image := "https://example.com/avatar.jpg"
	user := &models.User{
		ID:            "user-123",
		Email:         "test@example.com",
		EmailVerified: true,
		Name:          "Test User",
		Image:         &image,
	}

	resp := toUserResponse(user)

	if resp.ID != user.ID {
		t.Errorf("ID = %s, want %s", resp.ID, user.ID)
	}
	if resp.Email != user.Email {
		t.Errorf("Email = %s, want %s", resp.Email, user.Email)
	}
	if resp.EmailVerified != user.EmailVerified {
		t.Errorf("EmailVerified = %v, want %v", resp.EmailVerified, user.EmailVerified)
	}
	if resp.Name != user.Name {
		t.Errorf("Name = %s, want %s", resp.Name, user.Name)
	}
	if resp.Image == nil || *resp.Image != image {
		t.Errorf("Image = %v, want %s", resp.Image, image)
	}
}

func TestToUserResponse_NilImage(t *testing.T) {
	user := &models.User{
		ID:            "user-123",
		Email:         "test@example.com",
		EmailVerified: false,
		Name:          "Test User",
		Image:         nil,
	}

	resp := toUserResponse(user)

	if resp.Image != nil {
		t.Errorf("Image should be nil, got %v", resp.Image)
	}
}

func TestToSessionResponse(t *testing.T) {
	expiresAt := time.Now().Add(24 * time.Hour)
	session := &models.Session{
		ID:        "session-123",
		ExpiresAt: expiresAt,
	}

	resp := toSessionResponse(session)

	if resp.ID != session.ID {
		t.Errorf("ID = %s, want %s", resp.ID, session.ID)
	}
	if !resp.ExpiresAt.Equal(expiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", resp.ExpiresAt, expiresAt)
	}
}

func TestWriteJSON(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		data       any
		wantStatus int
		wantBody   string
	}{
		{
			name:       "success with data",
			status:     http.StatusOK,
			data:       map[string]string{"message": "hello"},
			wantStatus: http.StatusOK,
			wantBody:   `{"message":"hello"}`,
		},
		{
			name:       "created with data",
			status:     http.StatusCreated,
			data:       map[string]int{"id": 123},
			wantStatus: http.StatusCreated,
			wantBody:   `{"id":123}`,
		},
		{
			name:       "nil data",
			status:     http.StatusNoContent,
			data:       nil,
			wantStatus: http.StatusNoContent,
			wantBody:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeJSON(rec, tt.status, tt.data)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %s, want application/json", ct)
			}
			if tt.wantBody != "" {
				body := strings.TrimSpace(rec.Body.String())
				if body != tt.wantBody {
					t.Errorf("body = %s, want %s", body, tt.wantBody)
				}
			}
		})
	}
}

func TestWriteError(t *testing.T) {
	rec := httptest.NewRecorder()
	testErr := errors.New("something went wrong")

	writeError(rec, http.StatusBadRequest, testErr)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if errResp.Error != "Bad Request" {
		t.Errorf("Error = %s, want Bad Request", errResp.Error)
	}
	if errResp.Message != "something went wrong" {
		t.Errorf("Message = %s, want something went wrong", errResp.Message)
	}
}

func TestWriteError_DifferentStatuses(t *testing.T) {
	tests := []struct {
		status    int
		wantError string
	}{
		{http.StatusUnauthorized, "Unauthorized"},
		{http.StatusForbidden, "Forbidden"},
		{http.StatusNotFound, "Not Found"},
		{http.StatusInternalServerError, "Internal Server Error"},
	}

	for _, tt := range tests {
		t.Run(tt.wantError, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeError(rec, tt.status, errors.New("test error"))

			var errResp ErrorResponse
			if err := json.NewDecoder(rec.Body).Decode(&errResp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			if errResp.Error != tt.wantError {
				t.Errorf("Error = %s, want %s", errResp.Error, tt.wantError)
			}
		})
	}
}

func TestSetSessionCookie(t *testing.T) {
	auth := &Auth{
		config: Config{
			SessionCookie: "session",
			BaseURL:       "https://example.com",
		},
	}

	expiresAt := time.Now().Add(24 * time.Hour)
	session := &models.Session{
		ID:        "session-123",
		RawToken:  "raw-token-value",
		ExpiresAt: expiresAt,
	}

	rec := httptest.NewRecorder()
	auth.SetSessionCookie(rec, session)

	// Check cookie was set
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != "session" {
		t.Errorf("cookie name = %s, want session", cookie.Name)
	}
	if cookie.Value != "raw-token-value" {
		t.Errorf("cookie value = %s, want raw-token-value", cookie.Value)
	}
	if !cookie.HttpOnly {
		t.Error("cookie should be HttpOnly")
	}
	if !cookie.Secure {
		t.Error("cookie should be Secure for HTTPS")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie SameSite = %v, want Strict", cookie.SameSite)
	}

	// Check RawToken was cleared
	if session.RawToken != "" {
		t.Error("RawToken should be cleared after setting cookie")
	}
}

func TestSetSessionCookie_HTTP(t *testing.T) {
	auth := &Auth{
		config: Config{
			SessionCookie: "session",
			BaseURL:       "http://localhost:3000",
		},
	}

	session := &models.Session{
		ID:        "session-123",
		RawToken:  "raw-token-value",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	rec := httptest.NewRecorder()
	auth.SetSessionCookie(rec, session)

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Secure {
		t.Error("cookie should NOT be Secure for HTTP")
	}
}

func TestClearSessionCookie(t *testing.T) {
	auth := &Auth{
		config: Config{
			SessionCookie: "session",
		},
	}

	rec := httptest.NewRecorder()
	auth.ClearSessionCookie(rec)

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != "session" {
		t.Errorf("cookie name = %s, want session", cookie.Name)
	}
	if cookie.Value != "" {
		t.Errorf("cookie value should be empty, got %s", cookie.Value)
	}
	if cookie.MaxAge != -1 {
		t.Errorf("cookie MaxAge = %d, want -1", cookie.MaxAge)
	}
}

func TestGetSessionToken_FromCookie(t *testing.T) {
	auth := &Auth{
		config: Config{
			SessionCookie: "session",
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "session",
		Value: "token-from-cookie",
	})

	token := auth.GetSessionToken(req)
	if token != "token-from-cookie" {
		t.Errorf("token = %s, want token-from-cookie", token)
	}
}

func TestGetSessionToken_FromBearerHeader(t *testing.T) {
	auth := &Auth{
		config: Config{
			SessionCookie: "session",
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer bearer-token-value")

	token := auth.GetSessionToken(req)
	if token != "bearer-token-value" {
		t.Errorf("token = %s, want bearer-token-value", token)
	}
}

func TestGetSessionToken_CookieTakesPrecedence(t *testing.T) {
	auth := &Auth{
		config: Config{
			SessionCookie: "session",
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "session",
		Value: "cookie-token",
	})
	req.Header.Set("Authorization", "Bearer bearer-token")

	// Cookie should take precedence
	token := auth.GetSessionToken(req)
	if token != "cookie-token" {
		t.Errorf("token = %s, want cookie-token (cookie should take precedence)", token)
	}
}

func TestGetSessionToken_NoToken(t *testing.T) {
	auth := &Auth{
		config: Config{
			SessionCookie: "session",
		},
	}

	req := httptest.NewRequest("GET", "/", nil)

	token := auth.GetSessionToken(req)
	if token != "" {
		t.Errorf("token should be empty, got %s", token)
	}
}

func TestGetSessionToken_InvalidBearerFormat(t *testing.T) {
	auth := &Auth{
		config: Config{
			SessionCookie: "session",
		},
	}

	tests := []struct {
		name string
		auth string
		want string
	}{
		{"no Bearer prefix", "token-value", ""},
		{"Basic auth", "Basic dXNlcjpwYXNz", ""},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tt.auth != "" {
				req.Header.Set("Authorization", tt.auth)
			}

			token := auth.GetSessionToken(req)
			if token != tt.want {
				t.Errorf("token = %s, want %s", token, tt.want)
			}
		})
	}
}

func TestDecodeJSON(t *testing.T) {
	type testBody struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	body := `{"name":"test","value":42}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))

	var result testBody
	if err := decodeJSON(req, &result); err != nil {
		t.Fatalf("decodeJSON failed: %v", err)
	}

	if result.Name != "test" {
		t.Errorf("Name = %s, want test", result.Name)
	}
	if result.Value != 42 {
		t.Errorf("Value = %d, want 42", result.Value)
	}
}

func TestDecodeJSON_InvalidJSON(t *testing.T) {
	body := `{invalid json`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))

	var result map[string]any
	err := decodeJSON(req, &result)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestDecodeJSON_EmptyBody(t *testing.T) {
	req := httptest.NewRequest("POST", "/", strings.NewReader(""))

	var result map[string]any
	err := decodeJSON(req, &result)
	if err == nil {
		t.Error("expected error for empty body")
	}
}

func TestDecodeJSON_TypeMismatch(t *testing.T) {
	type testBody struct {
		Value int `json:"value"`
	}

	body := `{"value":"not-an-int"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))

	var result testBody
	err := decodeJSON(req, &result)
	if err == nil {
		t.Error("expected error for type mismatch")
	}
}

func TestErrorResponse_JSONMarshaling(t *testing.T) {
	resp := ErrorResponse{
		Error:   "Bad Request",
		Message: "invalid email format",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded ErrorResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Error != resp.Error {
		t.Errorf("Error = %s, want %s", decoded.Error, resp.Error)
	}
	if decoded.Message != resp.Message {
		t.Errorf("Message = %s, want %s", decoded.Message, resp.Message)
	}
}

func TestUserResponse_JSONMarshaling(t *testing.T) {
	image := "https://example.com/avatar.jpg"
	resp := UserResponse{
		ID:            "user-123",
		Email:         "test@example.com",
		EmailVerified: true,
		Name:          "Test User",
		Image:         &image,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded UserResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.ID != resp.ID {
		t.Errorf("ID = %s, want %s", decoded.ID, resp.ID)
	}
	if decoded.Email != resp.Email {
		t.Errorf("Email = %s, want %s", decoded.Email, resp.Email)
	}
	if decoded.EmailVerified != resp.EmailVerified {
		t.Errorf("EmailVerified = %v, want %v", decoded.EmailVerified, resp.EmailVerified)
	}
	if decoded.Name != resp.Name {
		t.Errorf("Name = %s, want %s", decoded.Name, resp.Name)
	}
	if decoded.Image == nil || *decoded.Image != image {
		t.Errorf("Image = %v, want %s", decoded.Image, image)
	}
}

func TestUserResponse_OmitsNilImage(t *testing.T) {
	resp := UserResponse{
		ID:            "user-123",
		Email:         "test@example.com",
		EmailVerified: false,
		Name:          "Test User",
		Image:         nil,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Check that "image" key is omitted
	if bytes.Contains(data, []byte(`"image"`)) {
		t.Error("nil image should be omitted from JSON")
	}
}

func TestSessionResponse_JSONMarshaling(t *testing.T) {
	expiresAt := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	resp := SessionResponse{
		ID:        "session-123",
		ExpiresAt: expiresAt,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded SessionResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.ID != resp.ID {
		t.Errorf("ID = %s, want %s", decoded.ID, resp.ID)
	}
	// Compare times with tolerance for JSON serialization
	if decoded.ExpiresAt.Unix() != expiresAt.Unix() {
		t.Errorf("ExpiresAt = %v, want %v", decoded.ExpiresAt, expiresAt)
	}
}

func TestDecodeJSON_LargeBody(t *testing.T) {
	type testBody struct {
		Data string `json:"data"`
	}

	// Create a large string
	largeData := strings.Repeat("x", 10000)
	body := `{"data":"` + largeData + `"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))

	var result testBody
	if err := decodeJSON(req, &result); err != nil {
		t.Fatalf("decodeJSON failed: %v", err)
	}

	if result.Data != largeData {
		t.Errorf("Data length = %d, want %d", len(result.Data), len(largeData))
	}
}

func TestDecodeJSON_NestedObject(t *testing.T) {
	type nested struct {
		Inner struct {
			Value string `json:"value"`
		} `json:"inner"`
	}

	body := `{"inner":{"value":"nested-value"}}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))

	var result nested
	if err := decodeJSON(req, &result); err != nil {
		t.Fatalf("decodeJSON failed: %v", err)
	}

	if result.Inner.Value != "nested-value" {
		t.Errorf("Inner.Value = %s, want nested-value", result.Inner.Value)
	}
}

func TestDecodeJSON_Array(t *testing.T) {
	body := `["a", "b", "c"]`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))

	var result []string
	if err := decodeJSON(req, &result); err != nil {
		t.Fatalf("decodeJSON failed: %v", err)
	}

	if len(result) != 3 {
		t.Fatalf("expected 3 elements, got %d", len(result))
	}
	if result[0] != "a" || result[1] != "b" || result[2] != "c" {
		t.Errorf("result = %v, want [a b c]", result)
	}
}

func TestDecodeJSON_ReaderError(t *testing.T) {
	// Create a reader that returns an error
	req := httptest.NewRequest("POST", "/", &errorReader{})

	var result map[string]any
	err := decodeJSON(req, &result)
	if err == nil {
		t.Error("expected error from reader")
	}
}

// errorReader is a reader that always returns an error
type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, io.ErrUnexpectedEOF
}
