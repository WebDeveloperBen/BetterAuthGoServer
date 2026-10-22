package oauth

import (
	"context"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
	"github.com/webdeveloperben/BetterAuthGoServer/db"
)

// The OAuth plugin exposes linked provider accounts to core so they are listed under
// GET /accounts, can be unlinked, and count towards last-sign-in-method protection.
var _ plugin.IdentityProvider = (*Plugin)(nil)

// ListIdentities returns the provider accounts linked to the user.
func (p *Plugin) ListIdentities(ctx context.Context, tx db.DBTX, userID string) ([]plugin.Identity, error) {
	if p.accountStore == nil {
		return nil, nil // plugin disabled (no database)
	}
	accounts, err := p.accountStoreFor(tx)
	if err != nil {
		return nil, err
	}
	linked, err := accounts.ListAccountsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	identities := make([]plugin.Identity, len(linked))
	for i, acc := range linked {
		identities[i] = plugin.Identity{
			ID:                acc.ID,
			UserID:            acc.UserID,
			Provider:          acc.Provider,
			ProviderAccountID: acc.ProviderAccountID,
			CreatedAt:         acc.CreatedAt,
			UpdatedAt:         acc.UpdatedAt,
		}
	}
	return identities, nil
}

// DeleteIdentity deletes a linked provider account.
func (p *Plugin) DeleteIdentity(ctx context.Context, tx db.DBTX, identityID string) error {
	if p.accountStore == nil {
		return nil
	}
	accounts, err := p.accountStoreFor(tx)
	if err != nil {
		return err
	}
	return accounts.DeleteAccount(ctx, identityID)
}
