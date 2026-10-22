package providers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func jsonServer(t *testing.T, path string, body any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer access-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestGitLab_Defaults(t *testing.T) {
	p := NewGitLab("id", "secret", "https://app.example.com/auth/oauth/gitlab/callback")

	assert.Equal(t, "gitlab", p.Name())
	assert.Equal(t, DefaultGitLabBaseURL, p.BaseURL())
	assert.Equal(t, "https://gitlab.com/oauth/authorize", p.Config().Endpoint.AuthURL)
	assert.Equal(t, "https://gitlab.com/oauth/token", p.Config().Endpoint.TokenURL)
	assert.ElementsMatch(t, []string{"openid", "profile", "email"}, p.Config().Scopes)
	assert.True(t, p.RequiresPKCE())
}

func TestGitLab_SelfManagedBaseURL(t *testing.T) {
	p := NewGitLab("id", "secret", "cb", WithGitLabBaseURL("https://gitlab.example.com/"))

	assert.Equal(t, "https://gitlab.example.com", p.BaseURL())
	assert.Equal(t, "https://gitlab.example.com/oauth/authorize", p.Config().Endpoint.AuthURL)
	assert.Equal(t, "https://gitlab.example.com/oauth/token", p.Config().Endpoint.TokenURL)
}

func TestGitLab_GetUserInfo(t *testing.T) {
	tests := []struct {
		name         string
		body         map[string]any
		wantEmail    string
		wantVerified bool
		wantName     string
	}{
		{
			name: "verified email",
			body: map[string]any{
				"sub": "42", "name": "Ada Lovelace", "nickname": "ada",
				"email": "ada@example.com", "email_verified": true,
				"picture": "https://gitlab.example.com/avatar.png",
			},
			wantEmail:    "ada@example.com",
			wantVerified: true,
			wantName:     "Ada Lovelace",
		},
		{
			name: "unverified email",
			body: map[string]any{
				"sub": "42", "nickname": "ada",
				"email": "ada@example.com", "email_verified": false,
			},
			wantEmail:    "ada@example.com",
			wantVerified: false,
			wantName:     "ada",
		},
		{
			name: "missing email_verified claim",
			body: map[string]any{
				"sub": "42", "name": "Ada", "email": "ada@example.com",
			},
			wantEmail:    "ada@example.com",
			wantVerified: false,
			wantName:     "Ada",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := jsonServer(t, "/oauth/userinfo", tt.body)
			p := NewGitLab("id", "secret", "cb", WithGitLabBaseURL(srv.URL))

			info, err := p.GetUserInfo(context.Background(), &oauth2.Token{AccessToken: "access-token"})
			require.NoError(t, err)

			assert.Equal(t, "42", info.ID)
			assert.Equal(t, tt.wantEmail, info.Email)
			assert.Equal(t, tt.wantVerified, info.EmailVerified)
			assert.Equal(t, tt.wantName, info.Name)
		})
	}
}

func TestGitLab_GetUserInfo_MissingSub(t *testing.T) {
	srv := jsonServer(t, "/oauth/userinfo", map[string]any{"email": "ada@example.com", "email_verified": true})
	p := NewGitLab("id", "secret", "cb", WithGitLabBaseURL(srv.URL))

	_, err := p.GetUserInfo(context.Background(), &oauth2.Token{AccessToken: "access-token"})
	require.Error(t, err)
}

func idToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func TestAzure_GetUserInfo_EmailVerification(t *testing.T) {
	graphUser := map[string]any{
		"id":                "object-id",
		"displayName":       "Ada Lovelace",
		"mail":              "ada@contoso.com",
		"userPrincipalName": "ada@contoso.onmicrosoft.com",
	}

	tests := []struct {
		name         string
		idClaims     map[string]any // nil: no id_token in the token response
		wantEmail    string
		wantVerified bool
	}{
		{
			name:         "graph mail without id token is not verified",
			idClaims:     nil,
			wantEmail:    "ada@contoso.com",
			wantVerified: false,
		},
		{
			name:         "id token email without verification claim is not verified",
			idClaims:     map[string]any{"aud": "client-id", "email": "ada@contoso.com"},
			wantEmail:    "ada@contoso.com",
			wantVerified: false,
		},
		{
			name:         "xms_edov false is not verified",
			idClaims:     map[string]any{"aud": "client-id", "email": "ada@contoso.com", "xms_edov": false},
			wantEmail:    "ada@contoso.com",
			wantVerified: false,
		},
		{
			name:         "verification claim for another audience is ignored",
			idClaims:     map[string]any{"aud": "other-client", "email": "ada@contoso.com", "xms_edov": true},
			wantEmail:    "ada@contoso.com",
			wantVerified: false,
		},
		{
			name:         "xms_edov true proves the id token email",
			idClaims:     map[string]any{"aud": "client-id", "email": "ada@contoso.com", "xms_edov": true},
			wantEmail:    "ada@contoso.com",
			wantVerified: true,
		},
		{
			name:         "email_verified true proves the id token email",
			idClaims:     map[string]any{"aud": []string{"client-id"}, "email": "ada.verified@contoso.com", "email_verified": "true"},
			wantEmail:    "ada.verified@contoso.com",
			wantVerified: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := jsonServer(t, "/v1.0/me", graphUser)
			p := NewAzure("client-id", "secret", "cb")
			p.graphMeURL = srv.URL + "/v1.0/me"

			token := &oauth2.Token{AccessToken: "access-token"}
			if tt.idClaims != nil {
				token = token.WithExtra(map[string]any{"id_token": idToken(t, tt.idClaims)})
			}

			info, err := p.GetUserInfo(context.Background(), token)
			require.NoError(t, err)

			assert.Equal(t, "object-id", info.ID)
			assert.Equal(t, tt.wantEmail, info.Email)
			assert.Equal(t, tt.wantVerified, info.EmailVerified)
		})
	}
}

func TestAzure_UPNFallbackIsNotVerified(t *testing.T) {
	srv := jsonServer(t, "/v1.0/me", map[string]any{
		"id":                "object-id",
		"userPrincipalName": "ada@contoso.onmicrosoft.com",
	})
	p := NewAzure("client-id", "secret", "cb")
	p.graphMeURL = srv.URL + "/v1.0/me"

	info, err := p.GetUserInfo(context.Background(), &oauth2.Token{AccessToken: "access-token"})
	require.NoError(t, err)

	assert.Equal(t, "ada@contoso.onmicrosoft.com", info.Email)
	assert.False(t, info.EmailVerified)
}

func TestSelectGitHubEmail(t *testing.T) {
	tests := []struct {
		name         string
		emails       []githubEmail
		wantEmail    string
		wantVerified bool
		wantErr      bool
	}{
		{
			name: "primary and verified",
			emails: []githubEmail{
				{Email: "secondary@example.com", Verified: true},
				{Email: "primary@example.com", Primary: true, Verified: true},
			},
			wantEmail:    "primary@example.com",
			wantVerified: true,
		},
		{
			name: "primary unverified is not verified even if a secondary is",
			emails: []githubEmail{
				{Email: "secondary@example.com", Verified: true},
				{Email: "primary@example.com", Primary: true},
			},
			wantEmail:    "primary@example.com",
			wantVerified: false,
		},
		{
			name:    "no primary email",
			emails:  []githubEmail{{Email: "secondary@example.com", Verified: true}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email, verified, err := selectGitHubEmail(tt.emails)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantEmail, email)
			assert.Equal(t, tt.wantVerified, verified)
		})
	}
}
