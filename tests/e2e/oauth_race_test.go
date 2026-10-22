package e2e

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/oauth"
	oauthdb "github.com/webdeveloperben/BetterAuthGoServer/auth/oauth/db"
	"github.com/webdeveloperben/BetterAuthGoServer/db"
)

func TestOAuthConcurrentRaces(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	for _, dialectEnv := range GetDialects() {
		t.Run(string(dialectEnv.Dialect), func(t *testing.T) {
			env := setupOAuth(t, dialectEnv)
			defer env.Cleanup(t)

			t.Run("UniqueViolationIsDetected", func(t *testing.T) {
				env.TruncateTables(t)
				env.CreateUser(t, "dup1@example.com", "password123!", "Dup 1")
				env.CreateUser(t, "dup2@example.com", "password123!", "Dup 2")
				store, err := oauthdb.New(env.DB, env.Dialect)
				require.NoError(t, err)
				now := time.Now()
				account := &oauthdb.Account{ID: "acc-1", UserID: env.userID(t, "dup1@example.com"), Provider: "fake", ProviderAccountID: "idp-dup", CreatedAt: now, UpdatedAt: now}
				require.NoError(t, store.CreateAccount(context.Background(), account))

				account.ID, account.UserID = "acc-2", env.userID(t, "dup2@example.com")
				err = store.CreateAccount(context.Background(), account)
				require.Error(t, err)
				assert.True(t, store.IsUniqueViolation(err), "unexpected error: %v", err)
				assert.False(t, store.IsUniqueViolation(context.Canceled))
			})

			t.Run("ConcurrentSignInsWithOneIdentityShareOneUser", func(t *testing.T) {
				for round := range 5 {
					env.TruncateTables(t)
					email := fmt.Sprintf("race%d@example.com", round)
					info := oauth.UserInfo{ID: fmt.Sprintf("idp-race-%d", round), Email: email, EmailVerified: true, Name: "Race"}

					codes := []string{fmt.Sprintf("race-%d-a", round), fmt.Sprintf("race-%d-b", round)}
					states := make([]string, len(codes))
					for i, code := range codes {
						env.idp.issue(code, info)
						states[i] = env.beginSignIn(t)
					}

					statuses := make([]int, len(codes))
					userIDs := make([]string, len(codes))
					start := make(chan struct{})
					var wg sync.WaitGroup
					for i := range codes {
						wg.Add(1)
						go func() {
							defer wg.Done()
							<-start
							resp := env.callback(t, codes[i], states[i], nil)
							statuses[i] = resp.StatusCode
							if resp.StatusCode == http.StatusOK {
								var body map[string]map[string]any
								DecodeResponse(t, resp, &body)
								userIDs[i], _ = body["user"]["id"].(string)
							} else {
								_ = resp.Body.Close()
							}
						}()
					}
					close(start)
					wg.Wait()

					assert.Equal(t, []int{http.StatusOK, http.StatusOK}, statuses, "round %d", round)
					assert.Equal(t, userIDs[0], userIDs[1], "round %d: both sign-ins must resolve to one user", round)
					assert.Equal(t, 1, env.count(t, "SELECT COUNT(*) FROM users"), "round %d", round)
					assert.Equal(t, 1, env.count(t, "SELECT COUNT(*) FROM oauth_accounts"), "round %d", round)
				}
			})

			t.Run("ConcurrentLinksOfOneIdentityConflict", func(t *testing.T) {
				for round := range 5 {
					env.TruncateTables(t)
					users := [][]*http.Cookie{
						env.CreateUser(t, fmt.Sprintf("judy%d@example.com", round), "password123!", "Judy"),
						env.CreateUser(t, fmt.Sprintf("mallory%d@example.com", round), "password123!", "Mallory"),
					}
					info := oauth.UserInfo{ID: fmt.Sprintf("idp-contested-%d", round), Name: "Contested"}

					codes := []string{fmt.Sprintf("link-%d-a", round), fmt.Sprintf("link-%d-b", round)}
					states := make([]string, len(codes))
					for i, code := range codes {
						env.idp.issue(code, info)
						states[i] = env.beginLink(t, "", users[i])
					}

					// On PostgreSQL and MySQL, hold an uncommitted insert of the contested
					// identity so both callbacks pass the "already linked?" check and block on
					// the unique index; rolling it back lets one insert win while the other
					// hits the unique violation. SQLite has no such row-level wait, so it
					// only checks the outcome of the plain race.
					var blocker *sql.Tx
					if env.Dialect != db.DialectSQLite {
						env.CreateUser(t, fmt.Sprintf("blocker%d@example.com", round), "password123!", "Blocker")
						blockerUserID := env.userID(t, fmt.Sprintf("blocker%d@example.com", round))
						var err error
						blocker, err = env.DB.BeginTx(context.Background(), nil)
						require.NoError(t, err)
						// Release the blocked callbacks even if the test fails before the explicit rollback.
						defer func() { _ = blocker.Rollback() }()
						now := time.Now()
						_, err = blocker.ExecContext(context.Background(), rebind(env.Dialect,
							"INSERT INTO oauth_accounts (id, user_id, provider, provider_account_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)"),
							"blocker", blockerUserID, "fake", info.ID, now, now)
						require.NoError(t, err)
					}

					statuses := make([]int, len(codes))
					start := make(chan struct{})
					var wg sync.WaitGroup
					for i := range codes {
						wg.Add(1)
						go func() {
							defer wg.Done()
							<-start
							resp := env.callback(t, codes[i], states[i], users[i])
							_ = resp.Body.Close()
							statuses[i] = resp.StatusCode
						}()
					}
					close(start)
					if blocker != nil {
						env.waitForLockWaiters(t, len(codes))
						require.NoError(t, blocker.Rollback())
					}
					wg.Wait()

					assert.ElementsMatch(t, []int{http.StatusOK, http.StatusConflict}, statuses, "round %d", round)
					assert.Equal(t, 1, env.count(t, "SELECT COUNT(*) FROM oauth_accounts"), "round %d", round)
				}
			})
		})
	}
}

// waitForLockWaiters waits until n account inserts are blocked behind the blocker
// transaction (PostgreSQL, MySQL).
func (e *oauthEnv) waitForLockWaiters(t *testing.T, n int) {
	t.Helper()
	query := "SELECT COUNT(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query LIKE '%CreateOAuthAccount%'"
	if e.Dialect == db.DialectMySQL {
		// INNODB_TRX needs the PROCESS privilege; a user always sees its own threads here.
		// Statements with arguments run as prepared statements (COMMAND 'Execute'). The
		// polling query matches its own pattern, so exclude this connection.
		query = "SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE COMMAND IN ('Query', 'Execute') AND ID <> CONNECTION_ID() AND INFO LIKE '%CreateOAuthAccount%'"
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting int
		require.NoError(t, e.DB.QueryRowContext(context.Background(), query).Scan(&waiting))
		if waiting >= n {
			return
		}
		require.True(t, time.Now().Before(deadline), "timed out waiting for %d lock waiters (have %d)", n, waiting)
		time.Sleep(10 * time.Millisecond)
	}
}
