package auth

import (
	"context"
	"html"
	"strings"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
)

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

// ListLinkedAccounts returns OAuth accounts linked to a user
func (a *Auth) ListLinkedAccounts(ctx context.Context, userID string) ([]*models.Account, error) {
	accounts, err := a.store.ListAccountsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Filter to only OAuth accounts (not email/password)
	oauthAccounts := make([]*models.Account, 0, len(accounts))
	for _, acc := range accounts {
		if acc.Provider != models.ProviderEmail {
			oauthAccounts = append(oauthAccounts, acc)
		}
	}

	return oauthAccounts, nil
}

// UnlinkAccount removes an OAuth account from a user
func (a *Auth) UnlinkAccount(ctx context.Context, userID string, provider string) error {
	// Get all accounts to check we're not removing the last one
	accounts, err := a.store.ListAccountsByUserID(ctx, userID)
	if err != nil {
		return err
	}

	// Find the account to remove
	var accountToRemove *models.Account
	for _, acc := range accounts {
		if string(acc.Provider) == provider {
			accountToRemove = acc
			break
		}
	}

	if accountToRemove == nil {
		return models.ErrAccountNotFound
	}

	// Check that we're not removing the only authentication method
	if len(accounts) <= 1 {
		return models.ErrCannotUnlinkLastAccount
	}

	// Delete the account
	return a.store.DeleteAccount(ctx, accountToRemove.ID)
}
