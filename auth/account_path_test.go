package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseAccountPath(t *testing.T) {
	tests := []struct {
		path      string
		provider  string
		accountID string
		ok        bool
	}{
		{"/accounts/github", "github", "", true},
		{"/accounts/github/acc-1", "github", "acc-1", true},
		{"/accounts/", "", "", false},
		{"/accounts/github/", "", "", false},
		{"/accounts//acc-1", "", "", false},
		{"/accounts/github/acc-1/extra", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			provider, accountID, ok := parseAccountPath(tt.path)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.provider, provider)
			assert.Equal(t, tt.accountID, accountID)
		})
	}
}
