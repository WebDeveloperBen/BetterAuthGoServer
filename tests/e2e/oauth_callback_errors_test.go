package e2e

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/oauth"
)

// callbackErrorTarget carries its own query to prove it is preserved.
const callbackErrorTarget = "/login?next=%2Fdashboard"

// errorRedirect asserts that resp redirects to callbackErrorTarget and returns the query
// it carries besides the preserved "next".
func errorRedirect(t *testing.T, resp *http.Response) url.Values {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Nil(t, GetSessionCookie(resp), "failed flows must not issue a session")
	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "/login", location.Path)
	query := location.Query()
	assert.Equal(t, "/dashboard", query.Get("next"), "the target's own query must be preserved")
	query.Del("next")
	return query
}

// providerErrorCallback simulates the provider redirecting back with an OAuth error response.
func (e *oauthEnv) providerErrorCallback(t *testing.T, providerError, state string, cookies []*http.Cookie) *http.Response {
	t.Helper()
	q := url.Values{"error": {providerError}, "error_description": {"<script>secret detail</script>"}, "state": {state}}
	return e.Get(t, "/auth/oauth/fake/callback?"+q.Encode(), cookies)
}

func TestOAuthCallbackErrorRedirect(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	for _, dialectEnv := range GetDialects() {
		t.Run(string(dialectEnv.Dialect), func(t *testing.T) {
			env := setupOAuthWith(t, dialectEnv, func(p *oauth.Plugin) {
				p.WithCallbackErrorRedirect(callbackErrorTarget)
			})
			defer env.Cleanup(t)

			signIn := func(code string) url.Values {
				return url.Values{"error": {code}, "provider": {"fake"}}
			}
			link := func(code string) url.Values {
				return url.Values{"error": {code}, "provider": {"fake"}, "flow": {"link"}}
			}

			t.Run("ProviderAccessDenied", func(t *testing.T) {
				env.TruncateTables(t)
				resp := env.providerErrorCallback(t, "access_denied", env.beginSignIn(t), nil)
				assert.Equal(t, signIn(oauth.CodeAccessDenied), errorRedirect(t, resp))
				assert.NotContains(t, resp.Header.Get("Location"), "secret")
				assert.Zero(t, env.count(t, "SELECT COUNT(*) FROM oauth_states"), "the state must be consumed")
				assert.Zero(t, env.count(t, "SELECT COUNT(*) FROM users"))
			})

			t.Run("OtherProviderErrorWithoutState", func(t *testing.T) {
				env.TruncateTables(t)
				resp := env.providerErrorCallback(t, "temporarily_unavailable", "", nil)
				assert.Equal(t, signIn(oauth.CodeProviderError), errorRedirect(t, resp))
			})

			t.Run("UnknownState", func(t *testing.T) {
				env.TruncateTables(t)
				resp := env.callback(t, "code-x", "unknown-state", nil)
				assert.Equal(t, signIn(oauth.CodeInvalidState), errorRedirect(t, resp))
			})

			t.Run("ExpiredState", func(t *testing.T) {
				env.TruncateTables(t)
				env.idp.issue("code-expired", oauth.UserInfo{ID: "idp-exp", Email: "exp@example.com", EmailVerified: true, Name: "Exp"})
				state := env.beginSignIn(t)
				_, err := env.DB.ExecContext(context.Background(),
					rebind(env.Dialect, "UPDATE oauth_states SET expires_at = ? WHERE state = ?"),
					time.Now().Add(-time.Hour).UTC(), state)
				require.NoError(t, err)

				resp := env.callback(t, "code-expired", state, nil)
				assert.Equal(t, signIn(oauth.CodeInvalidState), errorRedirect(t, resp))
				assert.Zero(t, env.count(t, "SELECT COUNT(*) FROM users"))
			})

			t.Run("MissingCode", func(t *testing.T) {
				env.TruncateTables(t)
				resp := env.Get(t, "/auth/oauth/fake/callback?state="+url.QueryEscape(env.beginSignIn(t)), nil)
				assert.Equal(t, signIn(oauth.CodeInvalidCallback), errorRedirect(t, resp))
			})

			t.Run("TokenExchangeFailure", func(t *testing.T) {
				env.TruncateTables(t)
				env.idp.reject("code-rejected")
				resp := env.callback(t, "code-rejected", env.beginSignIn(t), nil)
				assert.Equal(t, signIn(oauth.CodeProviderError), errorRedirect(t, resp))
				assert.Zero(t, env.count(t, "SELECT COUNT(*) FROM users"))
			})

			t.Run("UnverifiedEmail", func(t *testing.T) {
				env.TruncateTables(t)
				env.idp.issue("code-unverified", oauth.UserInfo{ID: "idp-u", Email: "u@example.com", EmailVerified: false, Name: "U"})
				resp := env.callback(t, "code-unverified", env.beginSignIn(t), nil)
				assert.Equal(t, signIn(oauth.CodeEmailNotVerified), errorRedirect(t, resp))
				assert.Zero(t, env.count(t, "SELECT COUNT(*) FROM users"))
			})

			t.Run("AccountExistsLinkRequired", func(t *testing.T) {
				env.TruncateTables(t)
				env.CreateUser(t, "alice@example.com", "password123!", "Alice")
				env.idp.issue("code-takeover", oauth.UserInfo{ID: "idp-m", Email: "alice@example.com", EmailVerified: true, Name: "Mallory"})
				resp := env.callback(t, "code-takeover", env.beginSignIn(t), nil)
				assert.Equal(t, signIn(oauth.CodeAccountExistsLinkRequired), errorRedirect(t, resp))
				assert.Zero(t, env.count(t, "SELECT COUNT(*) FROM oauth_accounts"))
			})

			t.Run("BannedUser", func(t *testing.T) {
				env.TruncateTables(t)
				info := oauth.UserInfo{ID: "idp-ivan", Email: "ivan@example.com", EmailVerified: true, Name: "Ivan"}
				env.signInWithIDP(t, "code-ivan", info)
				_, err := env.DB.ExecContext(context.Background(),
					rebind(env.Dialect, "UPDATE users SET banned = ? WHERE id = ?"), true, env.userID(t, "ivan@example.com"))
				require.NoError(t, err)

				env.idp.issue("code-ivan-again", info)
				resp := env.callback(t, "code-ivan-again", env.beginSignIn(t), nil)
				assert.Equal(t, signIn(oauth.CodeUserBanned), errorRedirect(t, resp))
			})

			t.Run("UnknownProviderOnBegin", func(t *testing.T) {
				env.TruncateTables(t)
				resp := env.Get(t, "/auth/oauth/nope", nil)
				assert.Equal(t, url.Values{"error": {oauth.CodeProviderNotFound}, "provider": {"nope"}}, errorRedirect(t, resp))
			})

			t.Run("DisallowedRedirectOnBegin", func(t *testing.T) {
				env.TruncateTables(t)
				resp := env.Get(t, "/auth/oauth/fake?redirect_to="+url.QueryEscape("https://evil.example.com/"), nil)
				assert.Equal(t, signIn(oauth.CodeInvalidRedirect), errorRedirect(t, resp))
				assert.Zero(t, env.count(t, "SELECT COUNT(*) FROM oauth_states"))
			})

			t.Run("FailedLinkCallbackCarriesFlowLink", func(t *testing.T) {
				env.TruncateTables(t)
				env.idp.issue("code-bob", oauth.UserInfo{ID: "idp-bob", Email: "bob@example.com", EmailVerified: true, Name: "Bob"})
				resp := env.callback(t, "code-bob", env.beginSignIn(t), nil)
				_ = resp.Body.Close()
				require.Equal(t, http.StatusOK, resp.StatusCode)

				cookies := env.CreateUser(t, "alice@example.com", "password123!", "Alice")

				env.idp.issue("code-steal", oauth.UserInfo{ID: "idp-bob", Name: "Bob"})
				resp = env.callback(t, "code-steal", env.beginLink(t, "", cookies), cookies)
				assert.Equal(t, link(oauth.CodeAccountAlreadyLinked), errorRedirect(t, resp))

				// Without the session that started the link.
				env.idp.issue("code-no-session", oauth.UserInfo{ID: "idp-alice", Name: "Alice"})
				resp = env.callback(t, "code-no-session", env.beginLink(t, "", cookies), nil)
				assert.Equal(t, link(oauth.CodeLinkSessionMismatch), errorRedirect(t, resp))

				// The user cancelled at the provider during a link.
				resp = env.providerErrorCallback(t, "access_denied", env.beginLink(t, "", cookies), cookies)
				assert.Equal(t, link(oauth.CodeAccessDenied), errorRedirect(t, resp))

				// Token exchange failure during a link.
				env.idp.reject("code-link-rejected")
				resp = env.callback(t, "code-link-rejected", env.beginLink(t, "", cookies), cookies)
				assert.Equal(t, link(oauth.CodeProviderError), errorRedirect(t, resp))

				assert.Equal(t, 1, env.count(t, "SELECT COUNT(*) FROM oauth_accounts"))
			})

			t.Run("LinkBeginStaysJSON", func(t *testing.T) {
				env.TruncateTables(t)
				cookies := env.CreateUser(t, "alice@example.com", "password123!", "Alice")
				resp := env.postLink(t, "redirect_to="+url.QueryEscape("https://evil.example.com/"), cookies)
				assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
				assert.Equal(t, oauth.CodeInvalidRedirect, decodeErrorBody(t, resp)["code"])
			})

			t.Run("SuccessIsUnchanged", func(t *testing.T) {
				env.TruncateTables(t)
				env.signInWithIDP(t, "code-ok", oauth.UserInfo{ID: "idp-ok", Email: "ok@example.com", EmailVerified: true, Name: "Ok"})
			})
		})
	}
}

// Without WithCallbackErrorRedirect, failures stay JSON {error, code}.
func TestOAuthCallbackErrorsJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	for _, dialectEnv := range GetDialects() {
		t.Run(string(dialectEnv.Dialect), func(t *testing.T) {
			env := setupOAuth(t, dialectEnv)
			defer env.Cleanup(t)

			cases := []struct {
				name string
				do   func(t *testing.T) *http.Response
				code string
			}{
				{"ProviderAccessDenied", func(t *testing.T) *http.Response {
					return env.providerErrorCallback(t, "access_denied", env.beginSignIn(t), nil)
				}, oauth.CodeAccessDenied},
				{"UnknownState", func(t *testing.T) *http.Response {
					return env.callback(t, "code-x", "unknown-state", nil)
				}, oauth.CodeInvalidState},
				{"MissingCode", func(t *testing.T) *http.Response {
					return env.Get(t, "/auth/oauth/fake/callback?state=abc", nil)
				}, oauth.CodeInvalidCallback},
				{"TokenExchangeFailure", func(t *testing.T) *http.Response {
					env.idp.reject("code-json-rejected")
					return env.callback(t, "code-json-rejected", env.beginSignIn(t), nil)
				}, oauth.CodeProviderError},
				{"UnknownProvider", func(t *testing.T) *http.Response {
					return env.Get(t, "/auth/oauth/nope", nil)
				}, oauth.CodeProviderNotFound},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					env.TruncateTables(t)
					resp := tc.do(t)
					assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
					assert.Empty(t, resp.Header.Get("Location"))
					body := decodeErrorBody(t, resp)
					assert.Equal(t, tc.code, body["code"])
					assert.Len(t, body, 2, "error responses carry only error and code")
					assert.NotContains(t, body["error"], "secret")
					assert.NotContains(t, body["error"], "invalid_grant")
				})
			}
		})
	}
}
