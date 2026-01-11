package deviceauth

import (
	"context"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/db"
)

// DeviceCodeStore defines the database operations required by the deviceauth plugin.
type DeviceCodeStore interface {
	// CreateDeviceCode stores a new device authorization code.
	CreateDeviceCode(ctx context.Context, code *DeviceCode) error
	// GetDeviceCodeByUserCode retrieves a device code by user code.
	GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error)
	// GetDeviceCodeByHash retrieves a device code by its hashed device code.
	GetDeviceCodeByHash(ctx context.Context, hashPrefix, fullHash string) (*DeviceCode, error)
	// UpdateDeviceCodeStatus updates the status and user ID of a device code.
	UpdateDeviceCodeStatus(ctx context.Context, id, status string, userID *string) error
	// UpdateDeviceCodeLastPolled updates the last polled timestamp.
	UpdateDeviceCodeLastPolled(ctx context.Context, id string, lastPolledAt time.Time) error
	// DeleteExpiredDeviceCodes removes expired device codes.
	DeleteExpiredDeviceCodes(ctx context.Context) (int64, error)
	// DeleteDeviceCode removes a device code by ID.
	DeleteDeviceCode(ctx context.Context, id string) error
}

// StoreAdapter adapts db.DeviceAuthStore to DeviceCodeStore.
type StoreAdapter struct {
	store db.DeviceAuthStore
}

// NewStoreAdapter creates a new StoreAdapter from a db.DeviceAuthStore.
func NewStoreAdapter(store db.DeviceAuthStore) *StoreAdapter {
	return &StoreAdapter{store: store}
}

// CreateDeviceCode stores a new device authorization code.
func (a *StoreAdapter) CreateDeviceCode(ctx context.Context, code *DeviceCode) error {
	dbCode := &db.DeviceCode{
		ID:              code.ID,
		DeviceCode:      code.DeviceCode,
		DeviceCodeHash:  code.DeviceCodeHash,
		UserCode:        code.UserCode,
		ClientID:        code.ClientID,
		Scope:           code.Scope,
		UserID:          code.UserID,
		Status:          string(code.Status),
		PollingInterval: code.PollingInterval,
		LastPolledAt:    code.LastPolledAt,
		ExpiresAt:       code.ExpiresAt,
		CreatedAt:       code.CreatedAt,
		UpdatedAt:       code.UpdatedAt,
	}
	return a.store.CreateDeviceCode(ctx, dbCode)
}

// GetDeviceCodeByUserCode retrieves a device code by user code.
func (a *StoreAdapter) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error) {
	dbCode, err := a.store.GetDeviceCodeByUserCode(ctx, userCode)
	if err != nil {
		return nil, err
	}
	if dbCode == nil {
		return nil, nil
	}
	return a.toDeviceCode(dbCode), nil
}

// GetDeviceCodeByHash retrieves a device code by its hashed device code.
func (a *StoreAdapter) GetDeviceCodeByHash(ctx context.Context, hashPrefix, fullHash string) (*DeviceCode, error) {
	dbCode, err := a.store.GetDeviceCodeByHash(ctx, hashPrefix, fullHash)
	if err != nil {
		return nil, err
	}
	if dbCode == nil {
		return nil, nil
	}
	return a.toDeviceCode(dbCode), nil
}

// UpdateDeviceCodeStatus updates the status and user ID of a device code.
func (a *StoreAdapter) UpdateDeviceCodeStatus(ctx context.Context, id, status string, userID *string) error {
	return a.store.UpdateDeviceCodeStatus(ctx, id, status, userID)
}

// UpdateDeviceCodeLastPolled updates the last polled timestamp.
func (a *StoreAdapter) UpdateDeviceCodeLastPolled(ctx context.Context, id string, lastPolledAt time.Time) error {
	return a.store.UpdateDeviceCodeLastPolled(ctx, id, lastPolledAt)
}

// DeleteExpiredDeviceCodes removes expired device codes.
func (a *StoreAdapter) DeleteExpiredDeviceCodes(ctx context.Context) (int64, error) {
	return a.store.DeleteExpiredDeviceCodes(ctx)
}

// DeleteDeviceCode removes a device code by ID.
func (a *StoreAdapter) DeleteDeviceCode(ctx context.Context, id string) error {
	return a.store.DeleteDeviceCode(ctx, id)
}

// toDeviceCode converts a db.DeviceCode to a local DeviceCode.
func (a *StoreAdapter) toDeviceCode(d *db.DeviceCode) *DeviceCode {
	return &DeviceCode{
		ID:              d.ID,
		DeviceCode:      d.DeviceCode,
		DeviceCodeHash:  d.DeviceCodeHash,
		UserCode:        d.UserCode,
		ClientID:        d.ClientID,
		Scope:           d.Scope,
		UserID:          d.UserID,
		Status:          DeviceCodeStatus(d.Status),
		PollingInterval: d.PollingInterval,
		LastPolledAt:    d.LastPolledAt,
		ExpiresAt:       d.ExpiresAt,
		CreatedAt:       d.CreatedAt,
		UpdatedAt:       d.UpdatedAt,
	}
}

// Ensure StoreAdapter implements DeviceCodeStore
var _ DeviceCodeStore = (*StoreAdapter)(nil)
