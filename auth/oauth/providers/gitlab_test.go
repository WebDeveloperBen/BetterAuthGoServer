package providers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"golang.org/x/oauth2"
)

func TestGitLabProviderUsesOpenIDConnect(t *testing.T) {
	var authorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/userinfo" {
			t.Errorf("request path = %q, want /oauth/userinfo", r.URL.Path)
		}
		authorization = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":"gitlab-subject","name":"GitLab User","email":"user@example.com","email_verified":true,"picture":"https://example.com/avatar.png"}`))
	}))
	defer server.Close()

	provider := NewGitLab("client", "secret", "https://app.example.com/callback",
		WithGitLabBaseURL(server.URL))
	if provider.Name() != "gitlab" || !provider.RequiresPKCE() {
		t.Fatalf("unexpected provider metadata: name=%q pkce=%v", provider.Name(), provider.RequiresPKCE())
	}
	if provider.BaseURL() != server.URL ||
		provider.Config().Endpoint.AuthURL != server.URL+"/oauth/authorize" ||
		provider.Config().Endpoint.TokenURL != server.URL+"/oauth/token" ||
		!reflect.DeepEqual(provider.Config().Scopes, []string{"openid", "profile", "email"}) {
		t.Fatalf("unexpected OAuth config: %#v", provider.Config())
	}

	info, err := provider.GetUserInfo(context.Background(), &oauth2.Token{AccessToken: "gitlab-token"})
	if err != nil {
		t.Fatal(err)
	}
	if authorization != "Bearer gitlab-token" {
		t.Fatalf("Authorization = %q", authorization)
	}
	if info.ID != "gitlab-subject" || info.Email != "user@example.com" || !info.EmailVerified ||
		info.Name != "GitLab User" || info.Picture != "https://example.com/avatar.png" {
		t.Fatalf("unexpected user info: %#v", info)
	}
}
