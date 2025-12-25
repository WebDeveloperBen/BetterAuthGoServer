package oauth

import (
	"testing"
)

func TestParseOAuthPath(t *testing.T) {
	tests := []struct {
		path               string
		expectedProvider   string
		expectedIsCallback bool
	}{
		{"/oauth/google", "google", false},
		{"/oauth/google/callback", "google", true},
		{"/oauth/github", "github", false},
		{"/oauth/github/callback", "github", true},
		{"/oauth/", "", false},
		{"/oauth", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
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
