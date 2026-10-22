package e2e

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/oauth"
	oauthdb "github.com/webdeveloperben/BetterAuthGoServer/auth/oauth/db"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
	"github.com/webdeveloperben/BetterAuthGoServer/db"
)

// fakeIDP is an OAuth authorization server whose token endpoint issues an access token
// per authorization code; the user info for each code is registered by the test.
type fakeIDP struct {
	server   *httptest.Server
	mu       sync.Mutex
	users    map[string]*oauth.UserInfo
	rejected map[string]bool
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	idp := &fakeIDP{users: make(map[string]*oauth.UserInfo), rejected: make(map[string]bool)}
	idp.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		code := r.PostForm.Get("code")
		w.Header().Set("Content-Type", "application/json")
		idp.mu.Lock()
		rejected := idp.rejected[code]
		idp.mu.Unlock()
		if rejected {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "at:" + code,
			"refresh_token": "rt:" + code,
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	}))
	t.Cleanup(idp.server.Close)
	return idp
}

// issue registers the user that will be returned for code.
func (idp *fakeIDP) issue(code string, info oauth.UserInfo) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.users[code] = &info
}

// reject makes the token endpoint refuse code with invalid_grant.
func (idp *fakeIDP) reject(code string) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.rejected[code] = true
}

func (idp *fakeIDP) provider() oauth.Provider {
	return &fakeProvider{idp: idp}
}

type fakeProvider struct {
	idp *fakeIDP
}

func (p *fakeProvider) Name() string { return "fake" }

func (p *fakeProvider) Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "http://localhost:3000/auth/oauth/fake/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:   p.idp.server.URL + "/authorize",
			TokenURL:  p.idp.server.URL + "/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
}

func (p *fakeProvider) GetUserInfo(_ context.Context, token *oauth2.Token) (*oauth.UserInfo, error) {
	p.idp.mu.Lock()
	defer p.idp.mu.Unlock()
	info, ok := p.idp.users[strings.TrimPrefix(token.AccessToken, "at:")]
	if !ok {
		return nil, errors.New("unknown access token")
	}
	copied := *info
	return &copied, nil
}

func (p *fakeProvider) RequiresPKCE() bool { return true }

// oauthEnv bundles a test environment with the fake identity provider.
type oauthEnv struct {
	*TestEnv
	idp *fakeIDP
}

func setupOAuth(t *testing.T, dialectEnv *DialectEnv) *oauthEnv {
	t.Helper()
	return setupOAuthWith(t, dialectEnv, nil)
}

// setupOAuthWith is setupOAuth with a hook that configures the plugin before registration.
func setupOAuthWith(t *testing.T, dialectEnv *DialectEnv, configure func(*oauth.Plugin)) *oauthEnv {
	t.Helper()
	idp := newFakeIDP(t)
	oauthPlugin, err := oauth.NewPlugin(idp.provider())
	require.NoError(t, err)
	if configure != nil {
		configure(oauthPlugin)
	}
	env := SetupWithDialectPlugins(t, dialectEnv, oauthPlugin)
	return &oauthEnv{TestEnv: env, idp: idp}
}

// stateFromURL extracts the OAuth state parameter from a provider authorize URL.
func stateFromURL(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	state := u.Query().Get("state")
	require.NotEmpty(t, state, "authorize URL has no state: %s", raw)
	return state
}

// beginSignIn starts a sign-in flow and returns its state.
func (e *oauthEnv) beginSignIn(t *testing.T) string {
	t.Helper()
	resp := e.Get(t, "/auth/oauth/fake", nil)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	return stateFromURL(t, resp.Header.Get("Location"))
}

// postLink calls POST /oauth/fake/link with the given cookies.
func (e *oauthEnv) postLink(t *testing.T, query string, cookies []*http.Cookie) *http.Response {
	t.Helper()
	path := "/auth/oauth/fake/link"
	if query != "" {
		path += "?" + query
	}
	return e.PostWithCookies(t, path, nil, cookies)
}

// beginLink starts a link flow for the session in cookies and returns its state.
func (e *oauthEnv) beginLink(t *testing.T, query string, cookies []*http.Cookie) string {
	t.Helper()
	resp := e.postLink(t, query, cookies)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]string
	DecodeResponse(t, resp, &body)
	return stateFromURL(t, body["url"])
}

// callback presents an authorization code and state to the callback endpoint.
func (e *oauthEnv) callback(t *testing.T, code, state string, cookies []*http.Cookie) *http.Response {
	t.Helper()
	q := url.Values{"code": {code}, "state": {state}}
	return e.Get(t, "/auth/oauth/fake/callback?"+q.Encode(), cookies)
}

func (e *oauthEnv) signIn(t *testing.T, email, password string) []*http.Cookie {
	t.Helper()
	resp := e.Post(t, "/auth/sign-in", map[string]string{"email": email, "password": password})
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return resp.Cookies()
}

// do sends a request with cookies and returns the response (redirects are not followed).
func (e *oauthEnv) do(t *testing.T, method, path string, cookies []*http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, e.Server.URL+path, nil)
	require.NoError(t, err)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// signInWithIDP signs in through the fake provider and returns the session cookies.
func (e *oauthEnv) signInWithIDP(t *testing.T, code string, info oauth.UserInfo) []*http.Cookie {
	t.Helper()
	e.idp.issue(code, info)
	resp := e.callback(t, code, e.beginSignIn(t), nil)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	cookie := GetSessionCookie(resp)
	require.NotNil(t, cookie)
	return []*http.Cookie{cookie}
}

// link links a provider identity to the user of cookies.
func (e *oauthEnv) link(t *testing.T, code string, info oauth.UserInfo, cookies []*http.Cookie) {
	t.Helper()
	e.idp.issue(code, info)
	resp := e.callback(t, code, e.beginLink(t, "", cookies), cookies)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func rebind(dialect db.Dialect, query string) string {
	if dialect != db.DialectPostgres {
		return query
	}
	var b strings.Builder
	n := 0
	for _, c := range query {
		if c == '?' {
			n++
			fmt.Fprintf(&b, "$%d", n)
			continue
		}
		b.WriteRune(c)
	}
	return b.String()
}

func (e *oauthEnv) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	require.NoError(t, e.DB.QueryRowContext(context.Background(), rebind(e.Dialect, query), args...).Scan(&n))
	return n
}

func (e *oauthEnv) userID(t *testing.T, email string) string {
	t.Helper()
	var id string
	require.NoError(t, e.DB.QueryRowContext(context.Background(),
		rebind(e.Dialect, "SELECT id FROM users WHERE email = ?"), email).Scan(&id))
	return id
}

// accountOwner returns the user owning the fake provider account, or "" if unlinked.
func (e *oauthEnv) accountOwner(t *testing.T, providerAccountID string) string {
	t.Helper()
	var owner string
	err := e.DB.QueryRowContext(context.Background(),
		rebind(e.Dialect, "SELECT user_id FROM oauth_accounts WHERE provider = ? AND provider_account_id = ?"),
		"fake", providerAccountID).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return ""
	}
	require.NoError(t, err)
	return owner
}

func decodeErrorBody(t *testing.T, resp *http.Response) map[string]string {
	t.Helper()
	var body map[string]string
	DecodeResponse(t, resp, &body)
	return body
}

func TestOAuthSignIn(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	for _, dialectEnv := range GetDialects() {
		t.Run(string(dialectEnv.Dialect), func(t *testing.T) {
			env := setupOAuth(t, dialectEnv)
			defer env.Cleanup(t)

			t.Run("UnverifiedEmailIsRejectedAndWritesNothing", func(t *testing.T) {
				env.TruncateTables(t)
				env.idp.issue("code-unverified", oauth.UserInfo{ID: "idp-1", Email: "new@example.com", EmailVerified: false, Name: "New"})

				resp := env.callback(t, "code-unverified", env.beginSignIn(t), nil)
				assert.Equal(t, http.StatusForbidden, resp.StatusCode)
				assert.Nil(t, GetSessionCookie(resp))
				assert.Equal(t, oauth.CodeEmailNotVerified, decodeErrorBody(t, resp)["code"])

				assert.Zero(t, env.count(t, "SELECT COUNT(*) FROM users"))
				assert.Zero(t, env.count(t, "SELECT COUNT(*) FROM oauth_accounts"))
				assert.Zero(t, env.count(t, "SELECT COUNT(*) FROM sessions"))
			})

			t.Run("EmailOfExistingUserIsConflictAndNotLinked", func(t *testing.T) {
				env.TruncateTables(t)
				env.CreateUser(t, "alice@example.com", "password123!", "Alice")
				aliceID := env.userID(t, "alice@example.com")
				sessionsBefore := env.count(t, "SELECT COUNT(*) FROM sessions WHERE user_id = ?", aliceID)

				env.idp.issue("code-takeover", oauth.UserInfo{ID: "idp-attacker", Email: "alice@example.com", EmailVerified: true, Name: "Mallory"})

				resp := env.callback(t, "code-takeover", env.beginSignIn(t), nil)
				assert.Equal(t, http.StatusConflict, resp.StatusCode)
				assert.Nil(t, GetSessionCookie(resp))
				body := decodeErrorBody(t, resp)
				assert.Equal(t, oauth.CodeAccountExistsLinkRequired, body["code"])
				assert.Len(t, body, 2, "conflict response must only carry error and code")
				assert.NotContains(t, body["error"], aliceID)

				assert.Equal(t, 1, env.count(t, "SELECT COUNT(*) FROM users"))
				assert.Zero(t, env.count(t, "SELECT COUNT(*) FROM oauth_accounts WHERE user_id = ?", aliceID))
				assert.Zero(t, env.count(t, "SELECT COUNT(*) FROM oauth_accounts"))
				assert.Equal(t, sessionsBefore, env.count(t, "SELECT COUNT(*) FROM sessions WHERE user_id = ?", aliceID))
			})

			t.Run("VerifiedNewEmailCreatesUserAccountAndSession", func(t *testing.T) {
				env.TruncateTables(t)
				env.idp.issue("code-new", oauth.UserInfo{ID: "idp-new", Email: "carol@example.com", EmailVerified: true, Name: "Carol"})

				resp := env.callback(t, "code-new", env.beginSignIn(t), nil)
				require.Equal(t, http.StatusOK, resp.StatusCode)
				assert.NotNil(t, GetSessionCookie(resp))
				var body map[string]map[string]any
				DecodeResponse(t, resp, &body)

				carolID := env.userID(t, "carol@example.com")
				assert.Equal(t, carolID, body["user"]["id"])
				assert.Equal(t, true, body["user"]["email_verified"])
				assert.Equal(t, carolID, env.accountOwner(t, "idp-new"))
				assert.Equal(t, 1, env.count(t, "SELECT COUNT(*) FROM sessions WHERE user_id = ?", carolID))

				// Signing in again with the same provider identity uses the linked account.
				env.idp.issue("code-new-again", oauth.UserInfo{ID: "idp-new", Email: "carol@example.com", EmailVerified: true, Name: "Carol"})
				resp = env.callback(t, "code-new-again", env.beginSignIn(t), nil)
				require.Equal(t, http.StatusOK, resp.StatusCode)
				DecodeResponse(t, resp, &body)
				assert.Equal(t, carolID, body["user"]["id"])
				assert.Equal(t, 1, env.count(t, "SELECT COUNT(*) FROM users"))
				assert.Equal(t, 1, env.count(t, "SELECT COUNT(*) FROM oauth_accounts"))
			})
		})
	}
}

// A failure after the user insert must roll back both the user and the plugin rows
// written through the transaction.
func TestCreatePluginUserTxRollsBack(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	for _, dialectEnv := range GetDialects() {
		t.Run(string(dialectEnv.Dialect), func(t *testing.T) {
			env := setupOAuth(t, dialectEnv)
			defer env.Cleanup(t)
			env.TruncateTables(t)

			failure := errors.New("forced failure")
			var txSeen bool
			_, err := env.Auth.CreatePluginUserTx(context.Background(), plugin.CreateUserRequest{
				Email: "rollback@example.com", Name: "Rollback", EmailVerified: true,
			}, func(ctx context.Context, tx db.DBTX, user *plugin.User) error {
				txSeen = tx != nil
				if tx == nil {
					return errors.New("no transaction")
				}
				store, err := oauthdb.New(tx, env.Dialect)
				if err != nil {
					return err
				}
				now := time.Now()
				if err := store.CreateAccount(ctx, &oauthdb.Account{
					ID: "acc-rollback", UserID: user.ID, Provider: "fake", ProviderAccountID: "idp-rollback",
					CreatedAt: now, UpdatedAt: now,
				}); err != nil {
					return err
				}
				return failure
			})

			assert.True(t, txSeen, "db.Store on *sql.DB must provide a transaction")
			require.ErrorIs(t, err, failure)
			assert.Zero(t, env.count(t, "SELECT COUNT(*) FROM users"))
			assert.Zero(t, env.count(t, "SELECT COUNT(*) FROM oauth_accounts"))
		})
	}
}

func TestOAuthExplicitLink(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	for _, dialectEnv := range GetDialects() {
		t.Run(string(dialectEnv.Dialect), func(t *testing.T) {
			env := setupOAuth(t, dialectEnv)
			defer env.Cleanup(t)

			t.Run("RequiresAuthentication", func(t *testing.T) {
				env.TruncateTables(t)
				resp := env.postLink(t, "", nil)
				defer func() { _ = resp.Body.Close() }()
				assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
				assert.Zero(t, env.count(t, "SELECT COUNT(*) FROM oauth_states"))
			})

			t.Run("RejectsDisallowedRedirect", func(t *testing.T) {
				env.TruncateTables(t)
				cookies := env.CreateUser(t, "alice@example.com", "password123!", "Alice")
				resp := env.postLink(t, "redirect_to="+url.QueryEscape("https://evil.example.com/"), cookies)
				defer func() { _ = resp.Body.Close() }()
				assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			})

			t.Run("HappyPath", func(t *testing.T) {
				env.TruncateTables(t)
				cookies := env.CreateUser(t, "alice@example.com", "password123!", "Alice")
				aliceID := env.userID(t, "alice@example.com")
				sessionsBefore := env.count(t, "SELECT COUNT(*) FROM sessions WHERE user_id = ?", aliceID)

				// The provider email differs and is unverified: linking proves control of both identities.
				env.idp.issue("code-link", oauth.UserInfo{ID: "idp-alice", Email: "alice@work.example.com", EmailVerified: false, Name: "Alice W"})

				resp := env.callback(t, "code-link", env.beginLink(t, "", cookies), cookies)
				require.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Nil(t, GetSessionCookie(resp), "linking must not issue a new session")
				var body map[string]any
				DecodeResponse(t, resp, &body)
				assert.Equal(t, true, body["linked"])

				assert.Equal(t, aliceID, env.accountOwner(t, "idp-alice"))
				assert.Equal(t, 1, env.count(t, "SELECT COUNT(*) FROM users"))
				assert.Equal(t, sessionsBefore, env.count(t, "SELECT COUNT(*) FROM sessions WHERE user_id = ?", aliceID))

				// Linking the same provider account again is idempotent.
				env.idp.issue("code-link-again", oauth.UserInfo{ID: "idp-alice", Email: "alice@work.example.com", Name: "Alice W"})
				resp = env.callback(t, "code-link-again", env.beginLink(t, "", cookies), cookies)
				_ = resp.Body.Close()
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, 1, env.count(t, "SELECT COUNT(*) FROM oauth_accounts"))

				// The linked identity now signs in as alice.
				env.idp.issue("code-signin", oauth.UserInfo{ID: "idp-alice", Email: "alice@work.example.com", Name: "Alice W"})
				resp = env.callback(t, "code-signin", env.beginSignIn(t), nil)
				require.Equal(t, http.StatusOK, resp.StatusCode)
				var signIn map[string]map[string]any
				DecodeResponse(t, resp, &signIn)
				assert.Equal(t, aliceID, signIn["user"]["id"])
			})

			t.Run("RedirectsToAllowedTarget", func(t *testing.T) {
				env.TruncateTables(t)
				cookies := env.CreateUser(t, "alice@example.com", "password123!", "Alice")
				env.idp.issue("code-redirect", oauth.UserInfo{ID: "idp-alice", Name: "Alice"})

				state := env.beginLink(t, "redirect_to="+url.QueryEscape("/settings/accounts"), cookies)
				resp := env.callback(t, "code-redirect", state, cookies)
				defer func() { _ = resp.Body.Close() }()
				assert.Equal(t, http.StatusFound, resp.StatusCode)
				assert.Equal(t, "/settings/accounts", resp.Header.Get("Location"))
				assert.Equal(t, env.userID(t, "alice@example.com"), env.accountOwner(t, "idp-alice"))
			})

			t.Run("AccountOwnedByAnotherUserIsConflict", func(t *testing.T) {
				env.TruncateTables(t)

				// Bob signs up through the provider.
				env.idp.issue("code-bob", oauth.UserInfo{ID: "idp-bob", Email: "bob@example.com", EmailVerified: true, Name: "Bob"})
				resp := env.callback(t, "code-bob", env.beginSignIn(t), nil)
				_ = resp.Body.Close()
				require.Equal(t, http.StatusOK, resp.StatusCode)
				bobID := env.userID(t, "bob@example.com")

				cookies := env.CreateUser(t, "alice@example.com", "password123!", "Alice")
				aliceID := env.userID(t, "alice@example.com")

				env.idp.issue("code-steal", oauth.UserInfo{ID: "idp-bob", Email: "bob@example.com", EmailVerified: true, Name: "Bob"})
				resp = env.callback(t, "code-steal", env.beginLink(t, "", cookies), cookies)
				assert.Equal(t, http.StatusConflict, resp.StatusCode)
				assert.Equal(t, oauth.CodeAccountAlreadyLinked, decodeErrorBody(t, resp)["code"])

				assert.Equal(t, bobID, env.accountOwner(t, "idp-bob"))
				assert.Zero(t, env.count(t, "SELECT COUNT(*) FROM oauth_accounts WHERE user_id = ?", aliceID))
				assert.Equal(t, 1, env.count(t, "SELECT COUNT(*) FROM oauth_accounts"))
			})

			t.Run("StateWithDifferentOrMissingSessionIsRejected", func(t *testing.T) {
				env.TruncateTables(t)
				aliceCookies := env.CreateUser(t, "alice@example.com", "password123!", "Alice")
				bobCookies := env.CreateUser(t, "bob@example.com", "password123!", "Bob")
				aliceOtherSession := env.signIn(t, "alice@example.com", "password123!")

				cases := []struct {
					name    string
					cookies []*http.Cookie
				}{
					{"missing session", nil},
					{"other session of the same user", aliceOtherSession},
					{"session of another user", bobCookies},
				}
				for i, tc := range cases {
					t.Run(tc.name, func(t *testing.T) {
						code := fmt.Sprintf("code-mismatch-%d", i)
						env.idp.issue(code, oauth.UserInfo{ID: "idp-victim", Email: "victim@example.com", EmailVerified: true, Name: "Victim"})

						state := env.beginLink(t, "", aliceCookies)
						resp := env.callback(t, code, state, tc.cookies)
						assert.Equal(t, http.StatusForbidden, resp.StatusCode)
						assert.Nil(t, GetSessionCookie(resp))
						assert.Equal(t, oauth.CodeLinkSessionMismatch, decodeErrorBody(t, resp)["code"])

						assert.Zero(t, env.count(t, "SELECT COUNT(*) FROM oauth_accounts"))
						assert.Equal(t, 2, env.count(t, "SELECT COUNT(*) FROM users"))
					})
				}
			})
		})
	}
}
