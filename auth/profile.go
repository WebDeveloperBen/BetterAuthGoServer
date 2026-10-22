package auth

import (
	"context"
	"errors"
	"html"
	"strings"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
	"github.com/webdeveloperben/BetterAuthGoServer/db"
)

// passwordPluginName is the registry name of the password plugin.
const passwordPluginName = "password"

// ProfileUpdates contains fields that can be updated by the user themselves
type ProfileUpdates struct {
	Name  *string
	Image *string
}

// UpdateProfile updates the current user's profile
func (a *Auth) UpdateProfile(ctx context.Context, userID string, updates ProfileUpdates) (*models.User, error) {
	user, err := a.store.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, models.ErrUserNotFound
	}

	// Apply updates
	if updates.Name != nil {
		name := strings.TrimSpace(*updates.Name)
		if len(name) < 1 || len(name) > 100 {
			return nil, models.ErrInvalidProfileUpdate
		}
		user.Name = html.EscapeString(name)
	}
	if updates.Image != nil {
		if len(*updates.Image) > 2048 {
			return nil, models.ErrInvalidProfileUpdate
		}
		user.Image = updates.Image
	}

	if err := a.store.UpdateUser(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}

// DeleteOwnAccount deletes the current user's account and all associated data
func (a *Auth) DeleteOwnAccount(ctx context.Context, userID string) error {
	user, err := a.store.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return models.ErrUserNotFound
	}

	// Delete all user sessions
	if err := a.store.DeleteSessionsByUserID(ctx, userID); err != nil {
		return err
	}

	// Delete all user accounts
	if err := a.store.DeleteAccountsByUserID(ctx, userID); err != nil {
		return err
	}

	// Delete the user
	return a.store.DeleteUser(ctx, userID)
}

// ListLinkedAccounts returns the sign-in identities linked to a user: core accounts other
// than email/password plus identities stored by plugins (e.g. OAuth provider accounts).
func (a *Auth) ListLinkedAccounts(ctx context.Context, userID string) ([]*models.Account, error) {
	accounts, err := a.store.ListAccountsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	linked := make([]*models.Account, 0, len(accounts))
	for _, account := range accounts {
		if account.Provider != models.ProviderEmail {
			linked = append(linked, account)
		}
	}

	for _, provider := range a.identityProviders() {
		identities, err := provider.ListIdentities(ctx, nil, userID)
		if err != nil {
			return nil, err
		}
		for _, identity := range identities {
			linked = append(linked, identityToAccount(identity))
		}
	}

	return linked, nil
}

// UnlinkAccount removes a linked sign-in identity from a user. accountID selects one
// account when the user has several for the provider; with an empty accountID the
// provider must match exactly one account (otherwise models.ErrAccountAmbiguous).
//
// It refuses with models.ErrCannotUnlinkLastAccount when the user would be left without
// a usable sign-in method. Usable methods are linked identities plus the password
// credential when the password plugin is registered. With a *db.Store the count and the
// delete run in one transaction holding a lock on the user, so concurrent unlinks
// cannot remove the last methods together.
func (a *Auth) UnlinkAccount(ctx context.Context, userID, provider, accountID string) error {
	if store, ok := a.store.(*db.Store); ok {
		err := store.InTx(ctx, func(txStore *db.Store, tx db.DBTX) error {
			if err := txStore.LockUser(ctx, userID); err != nil {
				return err
			}
			return a.unlinkAccount(ctx, txStore, tx, userID, provider, accountID)
		})
		if !errors.Is(err, db.ErrTxUnsupported) {
			return err
		}
	}
	// Stores without transaction support: best effort, not safe against concurrent unlinks.
	return a.unlinkAccount(ctx, a.store, nil, userID, provider, accountID)
}

// unlinkCandidate is a sign-in method of the user that can be unlinked.
type unlinkCandidate struct {
	id       string
	provider string
	usable   bool
	remove   func() error
}

func (a *Auth) unlinkAccount(ctx context.Context, store models.Store, tx db.DBTX, userID, provider, accountID string) error {
	coreAccounts, err := store.ListAccountsByUserID(ctx, userID)
	if err != nil {
		return err
	}

	passwordEnabled := a.plugins != nil && a.plugins.Get(passwordPluginName) != nil
	var candidates []unlinkCandidate
	for _, acc := range coreAccounts {
		usable := acc.Provider != models.ProviderEmail || (passwordEnabled && acc.PasswordHash != nil)
		candidates = append(candidates, unlinkCandidate{
			id:       acc.ID,
			provider: string(acc.Provider),
			usable:   usable,
			remove:   func() error { return store.DeleteAccount(ctx, acc.ID) },
		})
	}
	for _, identityProvider := range a.identityProviders() {
		identities, err := identityProvider.ListIdentities(ctx, tx, userID)
		if err != nil {
			return err
		}
		for _, identity := range identities {
			candidates = append(candidates, unlinkCandidate{
				id:       identity.ID,
				provider: identity.Provider,
				usable:   true,
				remove:   func() error { return identityProvider.DeleteIdentity(ctx, tx, identity.ID) },
			})
		}
	}

	usable := 0
	var matches []unlinkCandidate
	for _, c := range candidates {
		if c.usable {
			usable++
		}
		if c.provider == provider && (accountID == "" || c.id == accountID) {
			matches = append(matches, c)
		}
	}

	switch len(matches) {
	case 0:
		return models.ErrAccountNotFound
	case 1:
	default:
		return models.ErrAccountAmbiguous
	}

	target := matches[0]
	remaining := usable
	if target.usable {
		remaining--
	}
	if remaining < 1 {
		return models.ErrCannotUnlinkLastAccount
	}

	return target.remove()
}

// identityProviders returns the registered plugins that store sign-in identities.
func (a *Auth) identityProviders() []plugin.IdentityProvider {
	if a.plugins == nil {
		return nil
	}
	var providers []plugin.IdentityProvider
	for _, p := range a.plugins.Plugins() {
		if provider, ok := p.(plugin.IdentityProvider); ok {
			providers = append(providers, provider)
		}
	}
	return providers
}

func identityToAccount(identity plugin.Identity) *models.Account {
	providerAccountID := identity.ProviderAccountID
	return &models.Account{
		ID:                identity.ID,
		UserID:            identity.UserID,
		Provider:          models.ProviderType(identity.Provider),
		ProviderAccountID: &providerAccountID,
		CreatedAt:         identity.CreatedAt,
		UpdatedAt:         identity.UpdatedAt,
	}
}
