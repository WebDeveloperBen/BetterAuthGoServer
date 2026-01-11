// Package db provides database storage implementations for API key management.
package db

import (
	"context"
	"database/sql"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/apikey/db/pgstore"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/apikey/db/sqlitestore"
	coredb "github.com/webdeveloperben/BetterAuthGoServer/db"
)

// APIKey represents an API key for programmatic access.
type APIKey struct {
	ID                  string
	Name                *string
	Start               string
	Prefix              *string
	Key                 string
	KeyPrefix           string
	UserID              string
	RateLimitEnabled    bool
	RateLimitTimeWindow *int64
	RateLimitMax        *int32
	RequestCount        int32
	Remaining           *int32
	RefillInterval      *int64
	RefillAmount        *int32
	LastRefillAt        *time.Time
	Enabled             bool
	LastRequest         *time.Time
	ExpiresAt           *time.Time
	Permissions         *string
	Metadata            *string
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// Store wraps the sqlc-generated queries for API key operations.
type Store struct {
	dialect coredb.Dialect
	pgQ     *pgstore.Queries
	sqliteQ *sqlitestore.Queries
}

// New creates a new Store for API key operations.
func New(db coredb.DBTX, dialect coredb.Dialect) *Store {
	s := &Store{dialect: dialect}
	if dialect == coredb.DialectPostgres {
		s.pgQ = pgstore.New(db)
	} else {
		s.sqliteQ = sqlitestore.New(db)
	}
	return s
}

// CreateAPIKey stores a new API key.
func (s *Store) CreateAPIKey(ctx context.Context, key *APIKey) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.CreateAPIKey(ctx, pgstore.CreateAPIKeyParams{
			ID:                  key.ID,
			Name:                toNullString(key.Name),
			Start:               key.Start,
			Prefix:              toNullString(key.Prefix),
			Key:                 key.Key,
			KeyPrefix:           key.KeyPrefix,
			UserID:              key.UserID,
			RateLimitEnabled:    key.RateLimitEnabled,
			RateLimitTimeWindow: toNullInt64(key.RateLimitTimeWindow),
			RateLimitMax:        toNullInt32(key.RateLimitMax),
			RequestCount:        key.RequestCount,
			Remaining:           toNullInt32(key.Remaining),
			RefillInterval:      toNullInt64(key.RefillInterval),
			RefillAmount:        toNullInt32(key.RefillAmount),
			LastRefillAt:        toNullTime(key.LastRefillAt),
			Enabled:             key.Enabled,
			LastRequest:         toNullTime(key.LastRequest),
			ExpiresAt:           toNullTime(key.ExpiresAt),
			Permissions:         toNullString(key.Permissions),
			Metadata:            toNullString(key.Metadata),
			CreatedAt:           key.CreatedAt,
			UpdatedAt:           key.UpdatedAt,
		})
	}
	return s.sqliteQ.CreateAPIKey(ctx, sqlitestore.CreateAPIKeyParams{
		ID:                  key.ID,
		Name:                toNullString(key.Name),
		Start:               key.Start,
		Prefix:              toNullString(key.Prefix),
		Key:                 key.Key,
		KeyPrefix:           key.KeyPrefix,
		UserID:              key.UserID,
		RateLimitEnabled:    boolToInt64(key.RateLimitEnabled),
		RateLimitTimeWindow: toNullInt64(key.RateLimitTimeWindow),
		RateLimitMax:        toNullInt64FromInt32(key.RateLimitMax),
		RequestCount:        int64(key.RequestCount),
		Remaining:           toNullInt64FromInt32(key.Remaining),
		RefillInterval:      toNullInt64(key.RefillInterval),
		RefillAmount:        toNullInt64FromInt32(key.RefillAmount),
		LastRefillAt:        timeToNullString(key.LastRefillAt),
		Enabled:             boolToInt64(key.Enabled),
		LastRequest:         timeToNullString(key.LastRequest),
		ExpiresAt:           timeToNullString(key.ExpiresAt),
		Permissions:         toNullString(key.Permissions),
		Metadata:            toNullString(key.Metadata),
		CreatedAt:           key.CreatedAt.Format(time.RFC3339),
		UpdatedAt:           key.UpdatedAt.Format(time.RFC3339),
	})
}

// GetAPIKeyByID retrieves an API key by ID.
func (s *Store) GetAPIKeyByID(ctx context.Context, id string) (*APIKey, error) {
	if s.dialect == coredb.DialectPostgres {
		row, err := s.pgQ.GetAPIKeyByID(ctx, id)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, nil
			}
			return nil, err
		}
		return pgKeyToDomain(&row), nil
	}
	row, err := s.sqliteQ.GetAPIKeyByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteKeyToDomain(&row), nil
}

// GetAPIKeyByKeyPrefix retrieves API keys by key prefix.
func (s *Store) GetAPIKeyByKeyPrefix(ctx context.Context, keyPrefix string) ([]*APIKey, error) {
	if s.dialect == coredb.DialectPostgres {
		rows, err := s.pgQ.GetAPIKeyByKeyPrefix(ctx, keyPrefix)
		if err != nil {
			return nil, err
		}
		keys := make([]*APIKey, len(rows))
		for i, row := range rows {
			r := row
			keys[i] = pgKeyToDomain(&r)
		}
		return keys, nil
	}
	rows, err := s.sqliteQ.GetAPIKeyByKeyPrefix(ctx, keyPrefix)
	if err != nil {
		return nil, err
	}
	keys := make([]*APIKey, len(rows))
	for i, row := range rows {
		r := row
		keys[i] = sqliteKeyToDomain(&r)
	}
	return keys, nil
}

// ListAPIKeysByUserID retrieves all API keys for a user.
func (s *Store) ListAPIKeysByUserID(ctx context.Context, userID string) ([]*APIKey, error) {
	if s.dialect == coredb.DialectPostgres {
		rows, err := s.pgQ.ListAPIKeysByUserID(ctx, userID)
		if err != nil {
			return nil, err
		}
		keys := make([]*APIKey, len(rows))
		for i, row := range rows {
			r := row
			keys[i] = pgKeyToDomain(&r)
		}
		return keys, nil
	}
	rows, err := s.sqliteQ.ListAPIKeysByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	keys := make([]*APIKey, len(rows))
	for i, row := range rows {
		r := row
		keys[i] = sqliteKeyToDomain(&r)
	}
	return keys, nil
}

// UpdateAPIKey updates an API key.
func (s *Store) UpdateAPIKey(ctx context.Context, key *APIKey) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.UpdateAPIKey(ctx, pgstore.UpdateAPIKeyParams{
			ID:                  key.ID,
			Name:                toNullString(key.Name),
			RateLimitEnabled:    key.RateLimitEnabled,
			RateLimitTimeWindow: toNullInt64(key.RateLimitTimeWindow),
			RateLimitMax:        toNullInt32(key.RateLimitMax),
			Remaining:           toNullInt32(key.Remaining),
			RefillInterval:      toNullInt64(key.RefillInterval),
			RefillAmount:        toNullInt32(key.RefillAmount),
			Enabled:             key.Enabled,
			ExpiresAt:           toNullTime(key.ExpiresAt),
			Permissions:         toNullString(key.Permissions),
			Metadata:            toNullString(key.Metadata),
			UpdatedAt:           key.UpdatedAt,
		})
	}
	return s.sqliteQ.UpdateAPIKey(ctx, sqlitestore.UpdateAPIKeyParams{
		ID:                  key.ID,
		Name:                toNullString(key.Name),
		RateLimitEnabled:    boolToInt64(key.RateLimitEnabled),
		RateLimitTimeWindow: toNullInt64(key.RateLimitTimeWindow),
		RateLimitMax:        toNullInt64FromInt32(key.RateLimitMax),
		Remaining:           toNullInt64FromInt32(key.Remaining),
		RefillInterval:      toNullInt64(key.RefillInterval),
		RefillAmount:        toNullInt64FromInt32(key.RefillAmount),
		Enabled:             boolToInt64(key.Enabled),
		ExpiresAt:           timeToNullString(key.ExpiresAt),
		Permissions:         toNullString(key.Permissions),
		Metadata:            toNullString(key.Metadata),
		UpdatedAt:           key.UpdatedAt.Format(time.RFC3339),
	})
}

// UpdateAPIKeyUsage updates the usage stats of an API key.
func (s *Store) UpdateAPIKeyUsage(ctx context.Context, key *APIKey) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.UpdateAPIKeyUsage(ctx, pgstore.UpdateAPIKeyUsageParams{
			ID:           key.ID,
			RequestCount: key.RequestCount,
			Remaining:    toNullInt32(key.Remaining),
			LastRequest:  toNullTime(key.LastRequest),
			LastRefillAt: toNullTime(key.LastRefillAt),
			UpdatedAt:    key.UpdatedAt,
		})
	}
	return s.sqliteQ.UpdateAPIKeyUsage(ctx, sqlitestore.UpdateAPIKeyUsageParams{
		ID:           key.ID,
		RequestCount: int64(key.RequestCount),
		Remaining:    toNullInt64FromInt32(key.Remaining),
		LastRequest:  timeToNullString(key.LastRequest),
		LastRefillAt: timeToNullString(key.LastRefillAt),
		UpdatedAt:    key.UpdatedAt.Format(time.RFC3339),
	})
}

// DeleteAPIKey deletes an API key by ID.
func (s *Store) DeleteAPIKey(ctx context.Context, id string) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.DeleteAPIKey(ctx, id)
	}
	return s.sqliteQ.DeleteAPIKey(ctx, id)
}

// DeleteAPIKeysByUserID deletes all API keys for a user.
func (s *Store) DeleteAPIKeysByUserID(ctx context.Context, userID string) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.DeleteAPIKeysByUserID(ctx, userID)
	}
	return s.sqliteQ.DeleteAPIKeysByUserID(ctx, userID)
}

// DeleteExpiredAPIKeys deletes all expired API keys.
func (s *Store) DeleteExpiredAPIKeys(ctx context.Context) (int64, error) {
	now := time.Now()
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.DeleteExpiredAPIKeys(ctx, sql.NullTime{Time: now, Valid: true})
	}
	return s.sqliteQ.DeleteExpiredAPIKeys(ctx, sql.NullString{String: now.Format(time.RFC3339), Valid: true})
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

func toNullInt32(i *int32) sql.NullInt32 {
	if i == nil {
		return sql.NullInt32{}
	}
	return sql.NullInt32{Int32: *i, Valid: true}
}

func fromNullInt32(ni sql.NullInt32) *int32 {
	if !ni.Valid {
		return nil
	}
	return &ni.Int32
}

func toNullInt64(i *int64) sql.NullInt64 {
	if i == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *i, Valid: true}
}

func fromNullInt64(ni sql.NullInt64) *int64 {
	if !ni.Valid {
		return nil
	}
	return &ni.Int64
}

func toNullInt64FromInt32(i *int32) sql.NullInt64 {
	if i == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(*i), Valid: true}
}

func fromNullInt64ToInt32(ni sql.NullInt64) *int32 {
	if !ni.Valid {
		return nil
	}
	v := int32(ni.Int64)
	return &v
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

func boolToInt64(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func int64ToBool(i int64) bool {
	return i != 0
}

func pgKeyToDomain(row *pgstore.ApiKey) *APIKey {
	return &APIKey{
		ID:                  row.ID,
		Name:                fromNullString(row.Name),
		Start:               row.Start,
		Prefix:              fromNullString(row.Prefix),
		Key:                 row.Key,
		KeyPrefix:           row.KeyPrefix,
		UserID:              row.UserID,
		RateLimitEnabled:    row.RateLimitEnabled,
		RateLimitTimeWindow: fromNullInt64(row.RateLimitTimeWindow),
		RateLimitMax:        fromNullInt32(row.RateLimitMax),
		RequestCount:        row.RequestCount,
		Remaining:           fromNullInt32(row.Remaining),
		RefillInterval:      fromNullInt64(row.RefillInterval),
		RefillAmount:        fromNullInt32(row.RefillAmount),
		LastRefillAt:        fromNullTime(row.LastRefillAt),
		Enabled:             row.Enabled,
		LastRequest:         fromNullTime(row.LastRequest),
		ExpiresAt:           fromNullTime(row.ExpiresAt),
		Permissions:         fromNullString(row.Permissions),
		Metadata:            fromNullString(row.Metadata),
		CreatedAt:           row.CreatedAt,
		UpdatedAt:           row.UpdatedAt,
	}
}

func sqliteKeyToDomain(row *sqlitestore.ApiKey) *APIKey {
	key := &APIKey{
		ID:                  row.ID,
		Name:                fromNullString(row.Name),
		Start:               row.Start,
		Prefix:              fromNullString(row.Prefix),
		Key:                 row.Key,
		KeyPrefix:           row.KeyPrefix,
		UserID:              row.UserID,
		RateLimitEnabled:    int64ToBool(row.RateLimitEnabled),
		RateLimitTimeWindow: fromNullInt64(row.RateLimitTimeWindow),
		RateLimitMax:        fromNullInt64ToInt32(row.RateLimitMax),
		RequestCount:        int32(row.RequestCount),
		Remaining:           fromNullInt64ToInt32(row.Remaining),
		RefillInterval:      fromNullInt64(row.RefillInterval),
		RefillAmount:        fromNullInt64ToInt32(row.RefillAmount),
		LastRefillAt:        nullStringToTime(row.LastRefillAt),
		Enabled:             int64ToBool(row.Enabled),
		LastRequest:         nullStringToTime(row.LastRequest),
		ExpiresAt:           nullStringToTime(row.ExpiresAt),
		Permissions:         fromNullString(row.Permissions),
		Metadata:            fromNullString(row.Metadata),
	}
	if t, err := time.Parse(time.RFC3339, row.CreatedAt); err == nil {
		key.CreatedAt = t
	}
	if t, err := time.Parse(time.RFC3339, row.UpdatedAt); err == nil {
		key.UpdatedAt = t
	}
	return key
}
