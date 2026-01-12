// Package db provides database storage implementations for device authentication.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/deviceauth/db/mysqlstore"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/deviceauth/db/pgstore"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/deviceauth/db/sqlitestore"
	coredb "github.com/webdeveloperben/BetterAuthGoServer/db"
)

// =============================================================================
// Domain types
// =============================================================================

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

// =============================================================================
// Querier interface - each dialect implements this
// =============================================================================

// Querier defines all device code database operations.
// Each dialect implements this interface, handling type conversions internally.
type Querier interface {
	CreateDeviceCode(ctx context.Context, code *DeviceCode) error
	GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error)
	GetDeviceCodeByHash(ctx context.Context, hashPrefix, fullHash string) (*DeviceCode, error)
	UpdateDeviceCodeStatus(ctx context.Context, id, status string, userID *string) error
	UpdateDeviceCodeLastPolled(ctx context.Context, id string, lastPolledAt time.Time) error
	DeleteExpiredDeviceCodes(ctx context.Context) (int64, error)
	DeleteDeviceCode(ctx context.Context, id string) error
}

// =============================================================================
// Store - delegates to dialect-specific Querier
// =============================================================================

// Store wraps the sqlc-generated queries for device code operations.
type Store struct {
	q Querier
}

// New creates a new Store for device code operations.
func New(db coredb.DBTX, dialect coredb.Dialect) (*Store, error) {
	var q Querier

	switch dialect {
	case coredb.DialectPostgres:
		q = newPgAdapter(db)
	case coredb.DialectMySQL:
		q = newMysqlAdapter(db)
	case coredb.DialectSQLite:
		q = newSqliteAdapter(db)
	default:
		return nil, fmt.Errorf("unsupported dialect: %s", dialect)
	}

	return &Store{q: q}, nil
}

// Delegate to Querier

func (s *Store) CreateDeviceCode(ctx context.Context, code *DeviceCode) error {
	return s.q.CreateDeviceCode(ctx, code)
}

func (s *Store) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error) {
	return s.q.GetDeviceCodeByUserCode(ctx, userCode)
}

func (s *Store) GetDeviceCodeByHash(ctx context.Context, hashPrefix, fullHash string) (*DeviceCode, error) {
	return s.q.GetDeviceCodeByHash(ctx, hashPrefix, fullHash)
}

func (s *Store) UpdateDeviceCodeStatus(ctx context.Context, id, status string, userID *string) error {
	return s.q.UpdateDeviceCodeStatus(ctx, id, status, userID)
}

func (s *Store) UpdateDeviceCodeLastPolled(ctx context.Context, id string, lastPolledAt time.Time) error {
	return s.q.UpdateDeviceCodeLastPolled(ctx, id, lastPolledAt)
}

func (s *Store) DeleteExpiredDeviceCodes(ctx context.Context) (int64, error) {
	return s.q.DeleteExpiredDeviceCodes(ctx)
}

func (s *Store) DeleteDeviceCode(ctx context.Context, id string) error {
	return s.q.DeleteDeviceCode(ctx, id)
}

// =============================================================================
// PostgreSQL adapter
// =============================================================================

type pgAdapter struct {
	q *pgstore.Queries
}

func newPgAdapter(db coredb.DBTX) *pgAdapter {
	return &pgAdapter{q: pgstore.New(db)}
}

func (a *pgAdapter) CreateDeviceCode(ctx context.Context, code *DeviceCode) error {
	return a.q.CreateDeviceCode(ctx, pgstore.CreateDeviceCodeParams{
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

func (a *pgAdapter) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error) {
	row, err := a.q.GetDeviceCodeByUserCode(ctx, userCode)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return pgCodeToDomain(&row), nil
}

func (a *pgAdapter) GetDeviceCodeByHash(ctx context.Context, hashPrefix, fullHash string) (*DeviceCode, error) {
	row, err := a.q.GetDeviceCodeByHash(ctx, pgstore.GetDeviceCodeByHashParams{
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

func (a *pgAdapter) UpdateDeviceCodeStatus(ctx context.Context, id, status string, userID *string) error {
	return a.q.UpdateDeviceCodeStatus(ctx, pgstore.UpdateDeviceCodeStatusParams{
		ID:        id,
		Status:    status,
		UserID:    toNullString(userID),
		UpdatedAt: time.Now(),
	})
}

func (a *pgAdapter) UpdateDeviceCodeLastPolled(ctx context.Context, id string, lastPolledAt time.Time) error {
	return a.q.UpdateDeviceCodeLastPolled(ctx, pgstore.UpdateDeviceCodeLastPolledParams{
		ID:           id,
		LastPolledAt: sql.NullTime{Time: lastPolledAt, Valid: true},
		UpdatedAt:    time.Now(),
	})
}

func (a *pgAdapter) DeleteExpiredDeviceCodes(ctx context.Context) (int64, error) {
	return a.q.DeleteExpiredDeviceCodes(ctx)
}

func (a *pgAdapter) DeleteDeviceCode(ctx context.Context, id string) error {
	return a.q.DeleteDeviceCode(ctx, id)
}

var _ Querier = (*pgAdapter)(nil)

// =============================================================================
// MySQL adapter
// =============================================================================

type mysqlAdapter struct {
	q *mysqlstore.Queries
}

func newMysqlAdapter(db coredb.DBTX) *mysqlAdapter {
	return &mysqlAdapter{q: mysqlstore.New(db)}
}

func (a *mysqlAdapter) CreateDeviceCode(ctx context.Context, code *DeviceCode) error {
	return a.q.CreateDeviceCode(ctx, mysqlstore.CreateDeviceCodeParams{
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

func (a *mysqlAdapter) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error) {
	row, err := a.q.GetDeviceCodeByUserCode(ctx, userCode)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return mysqlCodeToDomain(&row), nil
}

func (a *mysqlAdapter) GetDeviceCodeByHash(ctx context.Context, hashPrefix, fullHash string) (*DeviceCode, error) {
	row, err := a.q.GetDeviceCodeByHash(ctx, mysqlstore.GetDeviceCodeByHashParams{
		DeviceCodeHash: hashPrefix,
		DeviceCode:     fullHash,
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return mysqlCodeToDomain(&row), nil
}

func (a *mysqlAdapter) UpdateDeviceCodeStatus(ctx context.Context, id, status string, userID *string) error {
	return a.q.UpdateDeviceCodeStatus(ctx, mysqlstore.UpdateDeviceCodeStatusParams{
		ID:        id,
		Status:    status,
		UserID:    toNullString(userID),
		UpdatedAt: time.Now(),
	})
}

func (a *mysqlAdapter) UpdateDeviceCodeLastPolled(ctx context.Context, id string, lastPolledAt time.Time) error {
	return a.q.UpdateDeviceCodeLastPolled(ctx, mysqlstore.UpdateDeviceCodeLastPolledParams{
		ID:           id,
		LastPolledAt: sql.NullTime{Time: lastPolledAt, Valid: true},
		UpdatedAt:    time.Now(),
	})
}

func (a *mysqlAdapter) DeleteExpiredDeviceCodes(ctx context.Context) (int64, error) {
	return a.q.DeleteExpiredDeviceCodes(ctx)
}

func (a *mysqlAdapter) DeleteDeviceCode(ctx context.Context, id string) error {
	return a.q.DeleteDeviceCode(ctx, id)
}

var _ Querier = (*mysqlAdapter)(nil)

// =============================================================================
// SQLite adapter
// =============================================================================

type sqliteAdapter struct {
	q *sqlitestore.Queries
}

func newSqliteAdapter(db coredb.DBTX) *sqliteAdapter {
	return &sqliteAdapter{q: sqlitestore.New(db)}
}

func (a *sqliteAdapter) CreateDeviceCode(ctx context.Context, code *DeviceCode) error {
	return a.q.CreateDeviceCode(ctx, sqlitestore.CreateDeviceCodeParams{
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

func (a *sqliteAdapter) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error) {
	row, err := a.q.GetDeviceCodeByUserCode(ctx, userCode)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteCodeToDomain(&row), nil
}

func (a *sqliteAdapter) GetDeviceCodeByHash(ctx context.Context, hashPrefix, fullHash string) (*DeviceCode, error) {
	row, err := a.q.GetDeviceCodeByHash(ctx, sqlitestore.GetDeviceCodeByHashParams{
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

func (a *sqliteAdapter) UpdateDeviceCodeStatus(ctx context.Context, id, status string, userID *string) error {
	return a.q.UpdateDeviceCodeStatus(ctx, sqlitestore.UpdateDeviceCodeStatusParams{
		ID:        id,
		Status:    status,
		UserID:    toNullString(userID),
		UpdatedAt: time.Now().Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) UpdateDeviceCodeLastPolled(ctx context.Context, id string, lastPolledAt time.Time) error {
	return a.q.UpdateDeviceCodeLastPolled(ctx, sqlitestore.UpdateDeviceCodeLastPolledParams{
		ID:           id,
		LastPolledAt: sql.NullString{String: lastPolledAt.Format(time.RFC3339), Valid: true},
		UpdatedAt:    time.Now().Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) DeleteExpiredDeviceCodes(ctx context.Context) (int64, error) {
	return a.q.DeleteExpiredDeviceCodes(ctx)
}

func (a *sqliteAdapter) DeleteDeviceCode(ctx context.Context, id string) error {
	return a.q.DeleteDeviceCode(ctx, id)
}

var _ Querier = (*sqliteAdapter)(nil)

// =============================================================================
// Conversion helpers
// =============================================================================

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

func mysqlCodeToDomain(row *mysqlstore.DeviceCode) *DeviceCode {
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
