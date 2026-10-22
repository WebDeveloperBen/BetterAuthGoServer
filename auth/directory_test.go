package auth_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/webdeveloperben/BetterAuthGoServer/auth"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/config"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/oauth"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/oauth/providers"
	"github.com/webdeveloperben/BetterAuthGoServer/db"
	"github.com/webdeveloperben/BetterAuthGoServer/migrate"
)

func TestLookupUsersIncludesSignInMethods(t *testing.T) {
	store := newMockStore()
	authService, err := auth.New(store,
		config.WithSecret("directory-test-secret-32-bytes-minimum"),
		config.WithBaseURL("http://localhost"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer authService.Close()

	now := time.Now()
	store.users["user-1"] = &models.User{ID: "user-1", Email: "one@example.com"}
	store.users["user-2"] = &models.User{ID: "user-2", Email: "two@example.com"}
	store.accounts["email-account"] = &models.Account{
		ID: "email-account", UserID: "user-1", Provider: models.ProviderEmail, CreatedAt: now,
	}
	store.accounts["github-account"] = &models.Account{
		ID: "github-account", UserID: "user-1", Provider: models.ProviderGitHub, CreatedAt: now.Add(time.Minute),
	}

	entries, err := authService.LookupUsers(context.Background(), []string{"user-1", "missing", "user-1", "user-2"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d users, want two existing distinct users", len(entries))
	}
	entry := entries["user-1"]
	if entry.User == nil || entry.User.Email != "one@example.com" {
		t.Fatalf("unexpected profile: %#v", entry.User)
	}
	if len(entry.SignInMethods) != 2 || entry.SignInMethods[0].Provider != "email" ||
		entry.SignInMethods[1].Provider != "github" {
		t.Fatalf("unexpected sign-in methods: %#v", entry.SignInMethods)
	}
	if entry.SignInMethods[0].CanUnlink || entry.SignInMethods[1].CanUnlink {
		t.Fatalf("unconfigured OAuth methods or passwordless email must not be unlinkable: %#v", entry.SignInMethods)
	}
	if len(entry.Providers) != 1 || entry.Providers[0] != "github" {
		t.Fatalf("unexpected providers: %#v", entry.Providers)
	}
	if methods, err := authService.ListSignInMethods(context.Background(), "missing"); err != nil || len(methods) != 0 {
		t.Fatalf("unknown user methods = %#v, error = %v", methods, err)
	}
}

func TestUnlinkAccountProtectsLastSignInMethod(t *testing.T) {
	store := newMockStore()
	authService, err := auth.New(store,
		config.WithSecret("directory-test-secret-32-bytes-minimum"),
		config.WithBaseURL("http://localhost"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer authService.Close()

	store.users["user-1"] = &models.User{ID: "user-1"}
	store.accounts["only-method"] = &models.Account{
		ID: "only-method", UserID: "user-1", Provider: models.ProviderGitHub,
	}
	if err := authService.UnlinkAccount(context.Background(), "user-1", "github", ""); !errors.Is(err, models.ErrCannotUnlinkLastAccount) {
		t.Fatalf("error = %v, want ErrCannotUnlinkLastAccount", err)
	}

	store.accounts["email-method"] = &models.Account{
		ID: "email-method", UserID: "user-1", Provider: models.ProviderEmail,
	}
	if err := authService.UnlinkAccount(context.Background(), "user-1", "github", ""); !errors.Is(err, models.ErrCannotUnlinkLastAccount) {
		t.Fatalf("email without the password plugin must not count as an alternative: %v", err)
	}
	store.accounts["google-method"] = &models.Account{
		ID: "google-method", UserID: "user-1", Provider: models.ProviderGoogle,
	}
	if err := authService.UnlinkAccount(context.Background(), "user-1", "github", ""); err != nil {
		t.Fatalf("UnlinkAccount() error = %v", err)
	}
	if _, exists := store.accounts["only-method"]; exists {
		t.Fatal("OAuth account was not removed")
	}
	if _, exists := store.accounts["email-method"]; !exists {
		t.Fatal("email sign-in account was removed")
	}
	if _, exists := store.accounts["google-method"]; !exists {
		t.Fatal("alternative sign-in account was removed")
	}
}

func TestConfiguredOAuthProvidersWithoutPlugin(t *testing.T) {
	authService, err := auth.New(newMockStore(),
		config.WithSecret("directory-test-secret-32-bytes-minimum"),
		config.WithBaseURL("http://localhost"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer authService.Close()
	if providers := authService.ConfiguredOAuthProviders(); len(providers) != 0 || providers == nil {
		t.Fatalf("ConfiguredOAuthProviders() = %#v, want empty non-nil slice", providers)
	}
}

func TestDirectoryWithOAuthPlugin(t *testing.T) {
	ctx := context.Background()
	database, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	database.SetMaxOpenConns(1)

	if err := migrate.Run(ctx, database, migrate.DialectSQLite, migrate.WithPlugins(oauth.Migrations())); err != nil {
		t.Fatal(err)
	}
	store, err := db.New(database, db.DialectSQLite)
	if err != nil {
		t.Fatal(err)
	}
	authService, err := auth.New(store,
		config.WithSecret("directory-test-secret-32-bytes-minimum"),
		config.WithBaseURL("http://localhost"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer authService.Close()
	oauthPlugin, err := oauth.NewPlugin(providers.NewGitHub(
		"client-id", "client-secret", "http://localhost/auth/oauth/github/callback",
	))
	if err != nil {
		t.Fatal(err)
	}
	authService.Use(oauthPlugin)
	if err := authService.Err(); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	user := &models.User{
		ID: "directory-oauth-user", Email: "directory-oauth@example.com",
		Name: "Directory OAuth User", Role: "user", CreatedAt: now, UpdatedAt: now,
	}
	if err := store.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateAccount(ctx, &models.Account{
		ID: "directory-email-account", UserID: user.ID,
		Provider: models.ProviderEmail, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
		INSERT INTO oauth_accounts
			(id, user_id, provider, provider_account_id, access_token, refresh_token, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"directory-github-account", user.ID, "github", "private-provider-id",
		"encrypted-access-token", "encrypted-refresh-token", now.Add(time.Minute).Format(time.RFC3339), now.Format(time.RFC3339),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
		INSERT INTO oauth_accounts
			(id, user_id, provider, provider_account_id, access_token, refresh_token, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"directory-github-account-2", user.ID, "github", "private-provider-id-2",
		"encrypted-access-token-2", "encrypted-refresh-token-2", now.Add(2*time.Minute).Format(time.RFC3339), now.Format(time.RFC3339),
	); err != nil {
		t.Fatal(err)
	}

	if providers := authService.ConfiguredOAuthProviders(); len(providers) != 1 || providers[0] != "github" {
		t.Fatalf("ConfiguredOAuthProviders() = %v", providers)
	}
	directory, err := authService.LookupUsers(ctx, []string{user.ID})
	if err != nil {
		t.Fatal(err)
	}
	entry := directory[user.ID]
	if entry.User == nil || len(entry.SignInMethods) != 3 || len(entry.Providers) != 1 {
		t.Fatalf("unexpected directory entry: %#v", entry)
	}
	if entry.SignInMethods[0].Provider != "email" || entry.SignInMethods[1].Provider != "github" ||
		entry.SignInMethods[2].Provider != "github" || entry.SignInMethods[0].CanUnlink ||
		!entry.SignInMethods[1].CanUnlink || !entry.SignInMethods[2].CanUnlink {
		t.Fatalf("unexpected sign-in methods: %#v", entry.SignInMethods)
	}
	if err := authService.UnlinkAccount(ctx, user.ID, "github", "directory-github-account"); err != nil {
		t.Fatalf("UnlinkAccount() error = %v", err)
	}
	methods, err := authService.ListSignInMethods(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(methods) != 2 || methods[0].Provider != "email" || methods[0].CanUnlink ||
		methods[1].Provider != "github" || methods[1].CanUnlink {
		t.Fatalf("unexpected remaining methods: %#v", methods)
	}
}
