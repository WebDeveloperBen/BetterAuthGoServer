package csrf

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNew(t *testing.T) {
	csrf := New()

	if csrf == nil {
		t.Fatal("New returned nil")
	}

	cfg := csrf.Config()
	if cfg.CookieName != "csrf_token" {
		t.Errorf("CookieName = %s, want csrf_token", cfg.CookieName)
	}
	if cfg.HeaderName != "X-CSRF-Token" {
		t.Errorf("HeaderName = %s, want X-CSRF-Token", cfg.HeaderName)
	}
}

func TestNew_WithOptions(t *testing.T) {
	csrf := New(
		WithCookieName("my_csrf"),
		WithHeaderName("X-My-CSRF"),
		WithBaseURL("https://example.com"),
	)

	cfg := csrf.Config()
	if cfg.CookieName != "my_csrf" {
		t.Errorf("CookieName = %s, want my_csrf", cfg.CookieName)
	}
	if cfg.HeaderName != "X-My-CSRF" {
		t.Errorf("HeaderName = %s, want X-My-CSRF", cfg.HeaderName)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.CookieName != "csrf_token" {
		t.Errorf("CookieName = %s, want csrf_token", cfg.CookieName)
	}
	if cfg.HeaderName != "X-CSRF-Token" {
		t.Errorf("HeaderName = %s, want X-CSRF-Token", cfg.HeaderName)
	}
	if cfg.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v, want %v", cfg.SameSite, http.SameSiteStrictMode)
	}
}

func TestMiddleware_SafeMethods(t *testing.T) {
	csrf := New()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := csrf.Middleware()(handler)

	safeMethods := []string{http.MethodGet, http.MethodHead, http.MethodOptions}
	for _, method := range safeMethods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/test", nil)
			rec := httptest.NewRecorder()
			wrapped.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("%s: status = %d, want %d", method, rec.Code, http.StatusOK)
			}

			// Should set CSRF cookie
			cookies := rec.Result().Cookies()
			found := false
			for _, c := range cookies {
				if c.Name == "csrf_token" {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s: CSRF cookie not set", method)
			}
		})
	}
}

func TestMiddleware_UnsafeMethods_MissingToken(t *testing.T) {
	csrf := New()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := csrf.Middleware()(handler)

	unsafeMethods := []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}
	for _, method := range unsafeMethods {
		t.Run(method+"_no_token", func(t *testing.T) {
			req := httptest.NewRequest(method, "/test", nil)
			rec := httptest.NewRecorder()
			wrapped.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Errorf("%s: status = %d, want %d", method, rec.Code, http.StatusForbidden)
			}
		})
	}
}

func TestMiddleware_UnsafeMethods_ValidToken(t *testing.T) {
	csrf := New()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := csrf.Middleware()(handler)

	// First, get a CSRF token via GET request
	getReq := httptest.NewRequest(http.MethodGet, "/test", nil)
	getRec := httptest.NewRecorder()
	wrapped.ServeHTTP(getRec, getReq)

	// Extract the CSRF cookie
	var csrfToken string
	for _, c := range getRec.Result().Cookies() {
		if c.Name == "csrf_token" {
			csrfToken = c.Value
			break
		}
	}

	if csrfToken == "" {
		t.Fatal("Failed to get CSRF token from GET request")
	}

	unsafeMethods := []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}
	for _, method := range unsafeMethods {
		t.Run(method+"_valid_token", func(t *testing.T) {
			req := httptest.NewRequest(method, "/test", nil)
			req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfToken})
			req.Header.Set("X-CSRF-Token", csrfToken)

			rec := httptest.NewRecorder()
			wrapped.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("%s: status = %d, want %d", method, rec.Code, http.StatusOK)
			}
		})
	}
}

func TestMiddleware_UnsafeMethods_MismatchedToken(t *testing.T) {
	csrf := New()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := csrf.Middleware()(handler)

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "cookie-token"})
	req.Header.Set("X-CSRF-Token", "header-token")

	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestMiddleware_UnsafeMethods_CookieOnlyNoHeader(t *testing.T) {
	csrf := New()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := csrf.Middleware()(handler)

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "some-token"})
	// No header

	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestIsSecure(t *testing.T) {
	tests := []struct {
		name     string
		opts     []Option
		expected bool
	}{
		{
			name:     "HTTPS URL",
			opts:     []Option{WithBaseURL("https://example.com")},
			expected: true,
		},
		{
			name:     "HTTP URL",
			opts:     []Option{WithBaseURL("http://example.com")},
			expected: false,
		},
		{
			name:     "Explicit secure true",
			opts:     []Option{WithSecure(true)},
			expected: true,
		},
		{
			name:     "Explicit secure false overrides HTTPS",
			opts:     []Option{WithBaseURL("https://example.com"), WithSecure(false)},
			expected: false,
		},
		{
			name:     "No URL",
			opts:     []Option{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			csrf := New(tt.opts...)
			if got := csrf.isSecure(); got != tt.expected {
				t.Errorf("isSecure() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestWithCustomErrorHandler(t *testing.T) {
	customCalled := false
	customHandler := func(w http.ResponseWriter, r *http.Request, err error) {
		customCalled = true
		http.Error(w, "custom error", http.StatusTeapot)
	}

	csrf := New(WithErrorHandler(customHandler))
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := csrf.Middleware()(handler)

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if !customCalled {
		t.Error("Custom error handler was not called")
	}
	if rec.Code != http.StatusTeapot {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusTeapot)
	}
}

func TestHeaderName(t *testing.T) {
	csrf := New(WithHeaderName("X-Custom-CSRF"))

	if csrf.HeaderName() != "X-Custom-CSRF" {
		t.Errorf("HeaderName() = %s, want X-Custom-CSRF", csrf.HeaderName())
	}
}

func TestCookieNotOverwritten(t *testing.T) {
	csrf := New()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := csrf.Middleware()(handler)

	// First request - should set cookie
	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec1 := httptest.NewRecorder()
	wrapped.ServeHTTP(rec1, req1)

	var firstToken string
	for _, c := range rec1.Result().Cookies() {
		if c.Name == "csrf_token" {
			firstToken = c.Value
			break
		}
	}

	// Second request with cookie - should not set a new cookie
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req2.AddCookie(&http.Cookie{Name: "csrf_token", Value: firstToken})
	rec2 := httptest.NewRecorder()
	wrapped.ServeHTTP(rec2, req2)

	// Should not have any Set-Cookie header
	setCookieHeaders := rec2.Result().Header["Set-Cookie"]
	if len(setCookieHeaders) > 0 {
		t.Error("Cookie was overwritten when it already existed")
	}
}
