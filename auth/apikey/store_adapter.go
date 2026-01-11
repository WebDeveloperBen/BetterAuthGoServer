package apikey

import (
	"context"

	apikeydb "github.com/webdeveloperben/BetterAuthGoServer/auth/apikey/db"
)

// KeyStore defines the interface for API key persistence.
// Implemented by StoreAdapter (sqlc).
type KeyStore interface {
	Create(ctx context.Context, key *APIKey) error
	GetByID(ctx context.Context, id string) (*APIKey, error)
	GetByIDAndUser(ctx context.Context, id, userID string) (*APIKey, error)
	ListByUser(ctx context.Context, userID string) ([]*APIKey, error)
	GetByKeyPrefix(ctx context.Context, keyPrefix string) ([]*APIKey, error)
	Update(ctx context.Context, key *APIKey) error
	UpdateUsage(ctx context.Context, key *APIKey) error
	Delete(ctx context.Context, id string) error
	DeleteAllExpired(ctx context.Context) (int64, error)
}

// StoreAdapter adapts apikeydb.Store to the apikey package's KeyStore interface.
type StoreAdapter struct {
	store *apikeydb.Store
}

// NewStoreAdapter creates a new API key store adapter from an apikeydb.Store.
func NewStoreAdapter(store *apikeydb.Store) *StoreAdapter {
	return &StoreAdapter{store: store}
}

// Create stores a new API key.
func (a *StoreAdapter) Create(ctx context.Context, key *APIKey) error {
	return a.store.CreateAPIKey(ctx, a.toDBKey(key))
}

// GetByID retrieves an API key by ID.
func (a *StoreAdapter) GetByID(ctx context.Context, id string) (*APIKey, error) {
	dbKey, err := a.store.GetAPIKeyByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if dbKey == nil {
		return nil, nil
	}
	return a.toAPIKey(dbKey), nil
}

// GetByIDAndUser retrieves an API key by ID, ensuring it belongs to the user.
func (a *StoreAdapter) GetByIDAndUser(ctx context.Context, id, userID string) (*APIKey, error) {
	dbKey, err := a.store.GetAPIKeyByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if dbKey == nil || dbKey.UserID != userID {
		return nil, nil
	}
	return a.toAPIKey(dbKey), nil
}

// ListByUser retrieves all API keys for a user.
func (a *StoreAdapter) ListByUser(ctx context.Context, userID string) ([]*APIKey, error) {
	dbKeys, err := a.store.ListAPIKeysByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	result := make([]*APIKey, len(dbKeys))
	for i, dbKey := range dbKeys {
		result[i] = a.toAPIKey(dbKey)
	}
	return result, nil
}

// GetByKeyPrefix retrieves API keys by key prefix for verification.
func (a *StoreAdapter) GetByKeyPrefix(ctx context.Context, keyPrefix string) ([]*APIKey, error) {
	dbKeys, err := a.store.GetAPIKeyByKeyPrefix(ctx, keyPrefix)
	if err != nil {
		return nil, err
	}
	result := make([]*APIKey, len(dbKeys))
	for i, dbKey := range dbKeys {
		result[i] = a.toAPIKey(dbKey)
	}
	return result, nil
}

// Update updates an API key.
func (a *StoreAdapter) Update(ctx context.Context, key *APIKey) error {
	return a.store.UpdateAPIKey(ctx, a.toDBKey(key))
}

// UpdateUsage updates the usage stats of an API key.
func (a *StoreAdapter) UpdateUsage(ctx context.Context, key *APIKey) error {
	return a.store.UpdateAPIKeyUsage(ctx, a.toDBKey(key))
}

// Delete removes an API key.
func (a *StoreAdapter) Delete(ctx context.Context, id string) error {
	return a.store.DeleteAPIKey(ctx, id)
}

// DeleteAllExpired removes all expired API keys.
func (a *StoreAdapter) DeleteAllExpired(ctx context.Context) (int64, error) {
	return a.store.DeleteExpiredAPIKeys(ctx)
}

// toDBKey converts an APIKey to an apikeydb.APIKey.
func (a *StoreAdapter) toDBKey(key *APIKey) *apikeydb.APIKey {
	rateLimitMax := int32(key.RateLimitMax)
	return &apikeydb.APIKey{
		ID:                  key.ID,
		Name:                key.Name,
		Start:               key.Start,
		Prefix:              key.Prefix,
		Key:                 key.Key,
		KeyPrefix:           key.KeyPrefix,
		UserID:              key.UserID,
		RateLimitEnabled:    key.RateLimitEnabled,
		RateLimitTimeWindow: &key.RateLimitTimeWindow,
		RateLimitMax:        &rateLimitMax,
		RequestCount:        int32(key.RequestCount),
		Remaining:           intPtrToInt32Ptr(key.Remaining),
		RefillInterval:      key.RefillInterval,
		RefillAmount:        intPtrToInt32Ptr(key.RefillAmount),
		LastRefillAt:        key.LastRefillAt,
		Enabled:             key.Enabled,
		LastRequest:         key.LastRequest,
		ExpiresAt:           key.ExpiresAt,
		Permissions:         key.Permissions,
		Metadata:            key.Metadata,
		CreatedAt:           key.CreatedAt,
		UpdatedAt:           key.UpdatedAt,
	}
}

// toAPIKey converts an apikeydb.APIKey to an APIKey.
func (a *StoreAdapter) toAPIKey(k *apikeydb.APIKey) *APIKey {
	var rateLimitTimeWindow int64
	if k.RateLimitTimeWindow != nil {
		rateLimitTimeWindow = *k.RateLimitTimeWindow
	}
	var rateLimitMax int
	if k.RateLimitMax != nil {
		rateLimitMax = int(*k.RateLimitMax)
	}

	return &APIKey{
		ID:                  k.ID,
		Name:                k.Name,
		Start:               k.Start,
		Prefix:              k.Prefix,
		Key:                 k.Key,
		KeyPrefix:           k.KeyPrefix,
		UserID:              k.UserID,
		RateLimitEnabled:    k.RateLimitEnabled,
		RateLimitTimeWindow: rateLimitTimeWindow,
		RateLimitMax:        rateLimitMax,
		RequestCount:        int(k.RequestCount),
		Remaining:           int32PtrToIntPtr(k.Remaining),
		RefillInterval:      k.RefillInterval,
		RefillAmount:        int32PtrToIntPtr(k.RefillAmount),
		LastRefillAt:        k.LastRefillAt,
		Enabled:             k.Enabled,
		LastRequest:         k.LastRequest,
		ExpiresAt:           k.ExpiresAt,
		Permissions:         k.Permissions,
		Metadata:            k.Metadata,
		CreatedAt:           k.CreatedAt,
		UpdatedAt:           k.UpdatedAt,
	}
}

func intPtrToInt32Ptr(i *int) *int32 {
	if i == nil {
		return nil
	}
	v := int32(*i)
	return &v
}

func int32PtrToIntPtr(i *int32) *int {
	if i == nil {
		return nil
	}
	v := int(*i)
	return &v
}

// Ensure StoreAdapter implements KeyStore
var _ KeyStore = (*StoreAdapter)(nil)
