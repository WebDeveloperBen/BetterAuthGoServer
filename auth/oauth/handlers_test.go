package oauth

import (
	"testing"
)

func TestParseOAuthPath(t *testing.T) {
	tests := []struct {
		name               string
		path               string
		expectedProvider   string
		expectedIsCallback bool
	}{
		{"google_auth", "/oauth/google", "google", false},
		{"google_callback", "/oauth/google/callback", "google", true},
		{"github_auth", "/oauth/github", "github", false},
		{"github_callback", "/oauth/github/callback", "github", true},
		{"trailing_slash", "/oauth/", "", false},
		{"no_trailing_slash", "/oauth", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, isCallback := parseOAuthPath(tt.path)
			if provider != tt.expectedProvider {
				t.Errorf("parseOAuthPath(%s) provider = %s, want %s", tt.path, provider, tt.expectedProvider)
			}
			if isCallback != tt.expectedIsCallback {
				t.Errorf("parseOAuthPath(%s) isCallback = %t, want %t", tt.path, isCallback, tt.expectedIsCallback)
			}
		})
	}
}
