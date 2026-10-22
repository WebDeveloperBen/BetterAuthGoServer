package e2e

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/oauth"
)

type linkedAccount struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
}

func (e *oauthEnv) listAccounts(t *testing.T, cookies []*http.Cookie) []linkedAccount {
	t.Helper()
	resp := e.Get(t, "/auth/accounts", cookies)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var accounts []linkedAccount
	DecodeResponse(t, resp, &accounts)
	return accounts
}

func (e *oauthEnv) unlink(t *testing.T, path string, cookies []*http.Cookie) int {
	t.Helper()
	resp := e.do(t, http.MethodDelete, path, cookies)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func (e *oauthEnv) accountID(t *testing.T, providerAccountID string) string {
	t.Helper()
	var id string
	require.NoError(t, e.DB.QueryRowContext(context.Background(),
		rebind(e.Dialect, "SELECT id FROM oauth_accounts WHERE provider = ? AND provider_account_id = ?"),
		"fake", providerAccountID).Scan(&id))
	return id
}

func TestUnlinkOAuthIdentities(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	for _, dialectEnv := range GetDialects() {
		t.Run(string(dialectEnv.Dialect), func(t *testing.T) {
			env := setupOAuth(t, dialectEnv)
			defer env.Cleanup(t)

			// newOAuthOnlyUser creates a user whose only sign-in methods are two provider identities.
			newOAuthOnlyUser := func(t *testing.T, name string) (cookies []*http.Cookie, userID string) {
				t.Helper()
				email := name + "@example.com"
				cookies = env.signInWithIDP(t, "code-"+name+"-1", oauth.UserInfo{ID: "idp-" + name + "-1", Email: email, EmailVerified: true, Name: name})
				env.link(t, "code-"+name+"-2", oauth.UserInfo{ID: "idp-" + name + "-2", Name: name}, cookies)
				return cookies, env.userID(t, email)
			}

			t.Run("ListsOAuthIdentities", func(t *testing.T) {
				env.TruncateTables(t)
				cookies, _ := newOAuthOnlyUser(t, "carol")

				accounts := env.listAccounts(t, cookies)
				require.Len(t, accounts, 2)
				ids := []string{accounts[0].ID, accounts[1].ID}
				assert.ElementsMatch(t, []string{env.accountID(t, "idp-carol-1"), env.accountID(t, "idp-carol-2")}, ids)
				assert.Equal(t, "fake", accounts[0].Provider)
			})

			t.Run("UnlinkOneOfTwoThenLastIsRefused", func(t *testing.T) {
				env.TruncateTables(t)
				cookies, userID := newOAuthOnlyUser(t, "dave")

				// Two accounts of the same provider: the provider alone is ambiguous.
				assert.Equal(t, http.StatusConflict, env.unlink(t, "/auth/accounts/fake", cookies))

				first := env.accountID(t, "idp-dave-1")
				assert.Equal(t, http.StatusNoContent, env.unlink(t, "/auth/accounts/fake/"+first, cookies))
				assert.Equal(t, 1, env.count(t, "SELECT COUNT(*) FROM oauth_accounts WHERE user_id = ?", userID))

				// The remaining identity is the last sign-in method (no password credential).
				assert.Equal(t, http.StatusBadRequest, env.unlink(t, "/auth/accounts/fake", cookies))
				second := env.accountID(t, "idp-dave-2")
				assert.Equal(t, http.StatusBadRequest, env.unlink(t, "/auth/accounts/fake/"+second, cookies))
				assert.Equal(t, 1, env.count(t, "SELECT COUNT(*) FROM oauth_accounts WHERE user_id = ?", userID))
			})

			t.Run("PasswordCountsAsSignInMethod", func(t *testing.T) {
				env.TruncateTables(t)
				cookies := env.CreateUser(t, "erin@example.com", "password123!", "Erin")
				env.link(t, "code-erin", oauth.UserInfo{ID: "idp-erin", Name: "Erin"}, cookies)

				assert.Equal(t, http.StatusNoContent, env.unlink(t, "/auth/accounts/fake", cookies))
				assert.Zero(t, env.count(t, "SELECT COUNT(*) FROM oauth_accounts"))
			})

			t.Run("CannotUnlinkAnotherUsersIdentity", func(t *testing.T) {
				env.TruncateTables(t)
				aliceCookies, _ := newOAuthOnlyUser(t, "alice")
				_, bobID := newOAuthOnlyUser(t, "bob")
				bobAccount := env.accountID(t, "idp-bob-1")

				assert.Equal(t, http.StatusNotFound, env.unlink(t, "/auth/accounts/fake/"+bobAccount, aliceCookies))
				assert.Equal(t, 2, env.count(t, "SELECT COUNT(*) FROM oauth_accounts WHERE user_id = ?", bobID))
			})

			t.Run("ConcurrentUnlinkLeavesExactlyOne", func(t *testing.T) {
				for round := range 5 {
					env.TruncateTables(t)
					cookies, userID := newOAuthOnlyUser(t, fmt.Sprintf("frank%d", round))
					ids := []string{
						env.accountID(t, fmt.Sprintf("idp-frank%d-1", round)),
						env.accountID(t, fmt.Sprintf("idp-frank%d-2", round)),
					}

					statuses := make([]int, len(ids))
					start := make(chan struct{})
					var wg sync.WaitGroup
					for i, id := range ids {
						wg.Add(1)
						go func() {
							defer wg.Done()
							<-start
							resp := env.do(t, http.MethodDelete, "/auth/accounts/fake/"+id, cookies)
							_ = resp.Body.Close()
							statuses[i] = resp.StatusCode
						}()
					}
					close(start)
					wg.Wait()

					assert.ElementsMatch(t, []int{http.StatusNoContent, http.StatusBadRequest}, statuses, "round %d", round)
					assert.Equal(t, 1, env.count(t, "SELECT COUNT(*) FROM oauth_accounts WHERE user_id = ?", userID), "round %d", round)
				}
			})
		})
	}
}
