package auth

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// SignInMethod describes one account that can authenticate a user.
// It contains no provider tokens or provider-specific account identifiers.
type SignInMethod struct {
	ID       string
	Provider string
	LinkedAt time.Time
	// CanUnlink is true only for OAuth methods when another sign-in method remains.
	CanUnlink bool
}

// DirectoryUser contains a user and the sign-in methods linked to that user.
type DirectoryUser struct {
	User          *models.User
	SignInMethods []SignInMethod
	// Providers contains distinct linked OAuth providers, excluding email/password.
	Providers []string
}

type oauthDirectory interface {
	ListLinkedAccountsByUserIDs(context.Context, []string) (map[string][]plugin.LinkedAccount, error)
	UnlinkLinkedAccount(context.Context, string, string) error
}

type batchDirectoryStore interface {
	GetUsersByIDs(context.Context, []string) ([]*models.User, error)
	ListAccountsByUserIDs(context.Context, []string) ([]*models.Account, error)
}

// ConfiguredOAuthProviders returns the configured OAuth provider names in
// stable order. It returns an empty slice when OAuth is not registered.
func (a *Auth) ConfiguredOAuthProviders() []string {
	if a.plugins == nil {
		return []string{}
	}
	provider, ok := a.plugins.Get("oauth").(interface{ ConfiguredProviders() []string })
	if !ok {
		return []string{}
	}
	return provider.ConfiguredProviders()
}

// LookupUsers loads users and their sign-in methods in batches. Missing users
// are omitted from the result; duplicate input IDs are queried only once.
func (a *Auth) LookupUsers(ctx context.Context, userIDs []string) (map[string]DirectoryUser, error) {
	result := make(map[string]DirectoryUser, len(userIDs))
	if len(userIDs) == 0 {
		return result, nil
	}

	ids := make([]string, 0, len(userIDs))
	seen := make(map[string]struct{}, len(userIDs))
	for _, userID := range userIDs {
		if _, exists := seen[userID]; exists {
			continue
		}
		seen[userID] = struct{}{}
		ids = append(ids, userID)
	}

	var err error
	var users []*models.User
	var accounts []*models.Account
	if batch, ok := a.store.(batchDirectoryStore); ok {
		users, err = batch.GetUsersByIDs(ctx, ids)
		if err != nil {
			return nil, err
		}
		accounts, err = batch.ListAccountsByUserIDs(ctx, ids)
		if err != nil {
			return nil, err
		}
	} else {
		users = make([]*models.User, 0, len(ids))
		accounts = make([]*models.Account, 0, len(ids))
		for _, userID := range ids {
			user, getErr := a.store.GetUserByID(ctx, userID)
			if getErr != nil && !errors.Is(getErr, models.ErrUserNotFound) {
				return nil, getErr
			}
			if user != nil {
				users = append(users, user)
			}
			userAccounts, listErr := a.store.ListAccountsByUserID(ctx, userID)
			if listErr != nil {
				return nil, listErr
			}
			accounts = append(accounts, userAccounts...)
		}
	}

	usersByID := make(map[string]*models.User, len(users))
	for _, user := range users {
		usersByID[user.ID] = user
	}

	methodsByUser := make(map[string][]SignInMethod, len(ids))
	usableMethodsByUser := make(map[string]int, len(ids))
	passwordEnabled := a.plugins != nil && a.plugins.Get(passwordPluginName) != nil
	for _, account := range accounts {
		methodsByUser[account.UserID] = append(methodsByUser[account.UserID], SignInMethod{
			ID: account.ID, Provider: string(account.Provider), LinkedAt: account.CreatedAt,
		})
		if account.Provider != models.ProviderEmail || (passwordEnabled && account.PasswordHash != nil) {
			usableMethodsByUser[account.UserID]++
		}
	}

	oauthProviders := make(map[string]struct{})
	for _, provider := range a.ConfiguredOAuthProviders() {
		oauthProviders[provider] = struct{}{}
	}

	var oauthAccounts map[string][]plugin.LinkedAccount
	if directory, ok := a.oauthDirectory(); ok {
		oauthAccounts, err = directory.ListLinkedAccountsByUserIDs(ctx, ids)
		if err != nil {
			return nil, err
		}
	}
	for userID, linked := range oauthAccounts {
		for _, account := range linked {
			methodsByUser[userID] = append(methodsByUser[userID], SignInMethod{
				ID: account.ID, Provider: account.Provider, LinkedAt: account.CreatedAt,
			})
			usableMethodsByUser[userID]++
		}
	}

	for _, identityProvider := range a.identityProviders() {
		if _, hasBatchDirectory := identityProvider.(oauthDirectory); hasBatchDirectory {
			continue
		}
		for _, userID := range ids {
			identities, err := identityProvider.ListIdentities(ctx, nil, userID)
			if err != nil {
				return nil, err
			}
			for _, identity := range identities {
				methodsByUser[userID] = append(methodsByUser[userID], SignInMethod{
					ID: identity.ID, Provider: identity.Provider, LinkedAt: identity.CreatedAt,
				})
				usableMethodsByUser[userID]++
			}
		}
	}

	for _, userID := range ids {
		user := usersByID[userID]
		if user == nil {
			continue
		}
		methods := methodsByUser[userID]
		slices.SortFunc(methods, compareSignInMethods)
		for index := range methods {
			_, isOAuth := oauthProviders[methods[index].Provider]
			methods[index].CanUnlink = isOAuth && usableMethodsByUser[userID] > 1
		}
		providers := make([]string, 0, len(methods))
		for _, method := range methods {
			if method.Provider != string(models.ProviderEmail) {
				providers = append(providers, method.Provider)
			}
		}
		slices.Sort(providers)
		providers = slices.Compact(providers)
		result[userID] = DirectoryUser{User: user, SignInMethods: methods, Providers: providers}
	}
	return result, nil
}

// ListSignInMethods returns a user's authentication methods, oldest first.
// An unknown user has no methods.
func (a *Auth) ListSignInMethods(ctx context.Context, userID string) ([]SignInMethod, error) {
	users, err := a.LookupUsers(ctx, []string{userID})
	if err != nil {
		return nil, err
	}
	if user, ok := users[userID]; ok {
		return user.SignInMethods, nil
	}
	return []SignInMethod{}, nil
}

func (a *Auth) oauthDirectory() (oauthDirectory, bool) {
	if a.plugins == nil {
		return nil, false
	}
	directory, ok := a.plugins.Get("oauth").(oauthDirectory)
	return directory, ok
}

func compareSignInMethods(left, right SignInMethod) int {
	if order := left.LinkedAt.Compare(right.LinkedAt); order != 0 {
		return order
	}
	if left.Provider < right.Provider {
		return -1
	}
	if left.Provider > right.Provider {
		return 1
	}
	if left.ID < right.ID {
		return -1
	}
	if left.ID > right.ID {
		return 1
	}
	return 0
}
