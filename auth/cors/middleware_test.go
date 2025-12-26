package cors

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCORS_TrustedOrigin(t *testing.T) {
	cors := New(
		WithOrigins("http://localhost:3000", "https://myapp.com"),
	)

	handler := cors.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name           string
		origin         string
		wantCORSHeader bool
	}{
		{
			name:           "trusted origin localhost",
			origin:         "http://localhost:3000",
			wantCORSHeader: true,
		},
		{
			name:           "trusted origin production",
			origin:         "https://myapp.com",
			wantCORSHeader: true,
		},
		{
			name:           "untrusted origin",
			origin:         "https://evil.com",
			wantCORSHeader: false,
		},
		{
			name:           "empty origin",
			origin:         "",
			wantCORSHeader: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			corsHeader := rec.Header().Get("Access-Control-Allow-Origin")
			if tt.wantCORSHeader && corsHeader == "" {
				t.Error("expected CORS header to be set")
			}
			if !tt.wantCORSHeader && corsHeader != "" {
				t.Errorf("expected no CORS header, got %s", corsHeader)
			}
		})
	}
}

func TestCORS_Preflight(t *testing.T) {
	cors := New(
		WithOrigins("http://localhost:3000"),
	)

	handler := cors.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("should not see this"))
	}))

	req := httptest.NewRequest(http.MethodOptions, "/test", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d", http.StatusNoContent, rec.Code)
	}

	if rec.Body.Len() > 0 {
		t.Error("expected empty body for preflight")
	}
}

func TestCORS_Headers(t *testing.T) {
	cors := New(
		WithOrigins("http://localhost:3000"),
		WithMethods("GET", "POST"),
		WithHeaders("Content-Type", "X-Custom"),
		WithExposeHeaders("X-Response"),
		WithMaxAge(3600),
	)

	handler := cors.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	tests := []struct {
		header string
		want   string
	}{
		{"Access-Control-Allow-Origin", "http://localhost:3000"},
		{"Access-Control-Allow-Credentials", "true"},
		{"Access-Control-Allow-Methods", "GET, POST"},
		{"Access-Control-Allow-Headers", "Content-Type, X-Custom"},
		{"Access-Control-Expose-Headers", "X-Response"},
		{"Access-Control-Max-Age", "3600"},
	}

	for _, tt := range tests {
		got := rec.Header().Get(tt.header)
		if got != tt.want {
			t.Errorf("header %s: expected %q, got %q", tt.header, tt.want, got)
		}
	}
}

func TestCORS_BaseURLTrusted(t *testing.T) {
	cors := New(
		WithBaseURL("http://localhost:8080"),
	)

	handler := cors.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "http://localhost:8080")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	corsHeader := rec.Header().Get("Access-Control-Allow-Origin")
	if corsHeader != "http://localhost:8080" {
		t.Errorf("expected base URL origin to be trusted, got %q", corsHeader)
	}
}

func TestCORS_NoCredentials(t *testing.T) {
	cors := New(
		WithOrigins("http://localhost:3000"),
		WithCredentials(false),
	)

	handler := cors.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Error("expected no credentials header when disabled")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if !cfg.AllowCredentials {
		t.Error("expected credentials to be allowed by default")
	}

	if cfg.MaxAge != 86400 {
		t.Errorf("expected max age 86400, got %d", cfg.MaxAge)
	}

	if len(cfg.AllowMethods) == 0 {
		t.Error("expected default methods")
	}

	if len(cfg.AllowHeaders) == 0 {
		t.Error("expected default headers")
	}
}
