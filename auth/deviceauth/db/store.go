package db

import (
	"context"
	"database/sql"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/deviceauth/db/pgstore"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/deviceauth/db/sqlitestore"
	coredb "github.com/webdeveloperben/BetterAuthGoServer/db"
)

// DeviceCode represents a device authorization code.
type DeviceCode struct {
	ID              string
	DeviceCode      string
	DeviceCodeHash  string
	UserCode        string
	ClientID        *string
	Scope           *string
	UserID          *string
	Status          string
	PollingInterval int
	LastPolledAt    *time.Time
	ExpiresAt       time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// Store wraps the sqlc-generated queries for device code operations.
type Store struct {
	dialect coredb.Dialect
	pgQ     *pgstore.Queries
	sqliteQ *sqlitestore.Queries
}

// New creates a new Store for device code operations.
func New(db coredb.DBTX, dialect coredb.Dialect) *Store {
	s := &Store{dialect: dialect}
	if dialect == coredb.DialectPostgres {
		s.pgQ = pgstore.New(db)
	} else {
		s.sqliteQ = sqlitestore.New(db)
	}
	return s
}

// CreateDeviceCode stores a new device authorization code.
func (s *Store) CreateDeviceCode(ctx context.Context, code *DeviceCode) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.CreateDeviceCode(ctx, pgstore.CreateDeviceCodeParams{
			ID:              code.ID,
			DeviceCode:      code.DeviceCode,
			DeviceCodeHash:  code.DeviceCodeHash,
			UserCode:        code.UserCode,
			ClientID:        toNullString(code.ClientID),
			Scope:           toNullString(code.Scope),
			UserID:          toNullString(code.UserID),
			Status:          code.Status,
			PollingInterval: int32(code.PollingInterval),
			LastPolledAt:    toNullTime(code.LastPolledAt),
			ExpiresAt:       code.ExpiresAt,
			CreatedAt:       code.CreatedAt,
			UpdatedAt:       code.UpdatedAt,
		})
	}
	return s.sqliteQ.CreateDeviceCode(ctx, sqlitestore.CreateDeviceCodeParams{
		ID:              code.ID,
		DeviceCode:      code.DeviceCode,
		DeviceCodeHash:  code.DeviceCodeHash,
		UserCode:        code.UserCode,
		ClientID:        toNullString(code.ClientID),
		Scope:           toNullString(code.Scope),
		UserID:          toNullString(code.UserID),
		Status:          code.Status,
		PollingInterval: int64(code.PollingInterval),
		LastPolledAt:    timeToNullString(code.LastPolledAt),
		ExpiresAt:       code.ExpiresAt.Format(time.RFC3339),
		CreatedAt:       code.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       code.UpdatedAt.Format(time.RFC3339),
	})
}

// GetDeviceCodeByUserCode retrieves a device code by user code.
func (s *Store) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error) {
	if s.dialect == coredb.DialectPostgres {
		row, err := s.pgQ.GetDeviceCodeByUserCode(ctx, userCode)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, nil
			}
			return nil, err
		}
		return pgCodeToDomain(&row), nil
	}
	row, err := s.sqliteQ.GetDeviceCodeByUserCode(ctx, userCode)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteCodeToDomain(&row), nil
}

// GetDeviceCodeByHash retrieves a device code by its hashed device code.
func (s *Store) GetDeviceCodeByHash(ctx context.Context, hashPrefix, fullHash string) (*DeviceCode, error) {
	if s.dialect == coredb.DialectPostgres {
		row, err := s.pgQ.GetDeviceCodeByHash(ctx, pgstore.GetDeviceCodeByHashParams{
			DeviceCodeHash: hashPrefix,
			DeviceCode:     fullHash,
		})
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, nil
			}
			return nil, err
		}
		return pgCodeToDomain(&row), nil
	}
	row, err := s.sqliteQ.GetDeviceCodeByHash(ctx, sqlitestore.GetDeviceCodeByHashParams{
		DeviceCodeHash: hashPrefix,
		DeviceCode:     fullHash,
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteCodeToDomain(&row), nil
}

// UpdateDeviceCodeStatus updates the status and user ID of a device code.
func (s *Store) UpdateDeviceCodeStatus(ctx context.Context, id, status string, userID *string) error {
	now := time.Now()
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.UpdateDeviceCodeStatus(ctx, pgstore.UpdateDeviceCodeStatusParams{
			ID:        id,
			Status:    status,
			UserID:    toNullString(userID),
			UpdatedAt: now,
		})
	}
	return s.sqliteQ.UpdateDeviceCodeStatus(ctx, sqlitestore.UpdateDeviceCodeStatusParams{
		ID:        id,
		Status:    status,
		UserID:    toNullString(userID),
		UpdatedAt: now.Format(time.RFC3339),
	})
}

// UpdateDeviceCodeLastPolled updates the last polled timestamp.
func (s *Store) UpdateDeviceCodeLastPolled(ctx context.Context, id string, lastPolledAt time.Time) error {
	now := time.Now()
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.UpdateDeviceCodeLastPolled(ctx, pgstore.UpdateDeviceCodeLastPolledParams{
			ID:           id,
			LastPolledAt: sql.NullTime{Time: lastPolledAt, Valid: true},
			UpdatedAt:    now,
		})
	}
	return s.sqliteQ.UpdateDeviceCodeLastPolled(ctx, sqlitestore.UpdateDeviceCodeLastPolledParams{
		ID:           id,
		LastPolledAt: sql.NullString{String: lastPolledAt.Format(time.RFC3339), Valid: true},
		UpdatedAt:    now.Format(time.RFC3339),
	})
}

// DeleteExpiredDeviceCodes removes expired device codes.
func (s *Store) DeleteExpiredDeviceCodes(ctx context.Context) (int64, error) {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.DeleteExpiredDeviceCodes(ctx)
	}
	return s.sqliteQ.DeleteExpiredDeviceCodes(ctx)
}

// DeleteDeviceCode removes a device code by ID.
func (s *Store) DeleteDeviceCode(ctx context.Context, id string) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.DeleteDeviceCode(ctx, id)
	}
	return s.sqliteQ.DeleteDeviceCode(ctx, id)
}

// ---- Conversion helpers ----

func toNullString(s *string) sql.NullString {
	if s == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *s, Valid: true}
}

func fromNullString(ns sql.NullString) *string {
	if !ns.Valid {
		return nil
	}
	return &ns.String
}

func toNullTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}

func fromNullTime(nt sql.NullTime) *time.Time {
	if !nt.Valid {
		return nil
	}
	return &nt.Time
}

func timeToNullString(t *time.Time) sql.NullString {
	if t == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: t.Format(time.RFC3339), Valid: true}
}

func nullStringToTime(ns sql.NullString) *time.Time {
	if !ns.Valid || ns.String == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, ns.String)
	if err != nil {
		return nil
	}
	return &t
}

func pgCodeToDomain(row *pgstore.DeviceCode) *DeviceCode {
	return &DeviceCode{
		ID:              row.ID,
		DeviceCode:      row.DeviceCode,
		DeviceCodeHash:  row.DeviceCodeHash,
		UserCode:        row.UserCode,
		ClientID:        fromNullString(row.ClientID),
		Scope:           fromNullString(row.Scope),
		UserID:          fromNullString(row.UserID),
		Status:          row.Status,
		PollingInterval: int(row.PollingInterval),
		LastPolledAt:    fromNullTime(row.LastPolledAt),
		ExpiresAt:       row.ExpiresAt,
		CreatedAt:       row.CreatedAt,
		UpdatedAt:       row.UpdatedAt,
	}
}

func sqliteCodeToDomain(row *sqlitestore.DeviceCode) *DeviceCode {
	code := &DeviceCode{
		ID:              row.ID,
		DeviceCode:      row.DeviceCode,
		DeviceCodeHash:  row.DeviceCodeHash,
		UserCode:        row.UserCode,
		ClientID:        fromNullString(row.ClientID),
		Scope:           fromNullString(row.Scope),
		UserID:          fromNullString(row.UserID),
		Status:          row.Status,
		PollingInterval: int(row.PollingInterval),
		LastPolledAt:    nullStringToTime(row.LastPolledAt),
	}
	if t, err := time.Parse(time.RFC3339, row.ExpiresAt); err == nil {
		code.ExpiresAt = t
	}
	if t, err := time.Parse(time.RFC3339, row.CreatedAt); err == nil {
		code.CreatedAt = t
	}
	if t, err := time.Parse(time.RFC3339, row.UpdatedAt); err == nil {
		code.UpdatedAt = t
	}
	return code
}
