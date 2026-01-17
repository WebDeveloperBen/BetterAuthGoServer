// Package db provides database storage implementations for API key management.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/apikey/db/mysqlstore"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/apikey/db/pgstore"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/apikey/db/sqlitestore"
	coredb "github.com/webdeveloperben/BetterAuthGoServer/db"
)

// =============================================================================
// Domain types
// =============================================================================

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

// =============================================================================
// Querier interface - each dialect implements this
// =============================================================================

// Querier defines all API key database operations.
// Each dialect implements this interface, handling type conversions internally.
type Querier interface {
	CreateAPIKey(ctx context.Context, key *APIKey) error
	GetAPIKeyByID(ctx context.Context, id string) (*APIKey, error)
	GetAPIKeyByKeyPrefix(ctx context.Context, keyPrefix string) ([]*APIKey, error)
	ListAPIKeysByUserID(ctx context.Context, userID string) ([]*APIKey, error)
	UpdateAPIKey(ctx context.Context, key *APIKey) error
	UpdateAPIKeyUsage(ctx context.Context, key *APIKey) error
	DeleteAPIKey(ctx context.Context, id string) error
	DeleteAPIKeysByUserID(ctx context.Context, userID string) error
	DeleteExpiredAPIKeys(ctx context.Context) (int64, error)
}

// =============================================================================
// Store - delegates to dialect-specific Querier
// =============================================================================

// Store wraps the sqlc-generated queries for API key operations.
type Store struct {
	q Querier
}

// New creates a new Store for API key operations.
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

func (s *Store) CreateAPIKey(ctx context.Context, key *APIKey) error {
	return s.q.CreateAPIKey(ctx, key)
}

func (s *Store) GetAPIKeyByID(ctx context.Context, id string) (*APIKey, error) {
	return s.q.GetAPIKeyByID(ctx, id)
}

func (s *Store) GetAPIKeyByKeyPrefix(ctx context.Context, keyPrefix string) ([]*APIKey, error) {
	return s.q.GetAPIKeyByKeyPrefix(ctx, keyPrefix)
}

func (s *Store) ListAPIKeysByUserID(ctx context.Context, userID string) ([]*APIKey, error) {
	return s.q.ListAPIKeysByUserID(ctx, userID)
}

func (s *Store) UpdateAPIKey(ctx context.Context, key *APIKey) error {
	return s.q.UpdateAPIKey(ctx, key)
}

func (s *Store) UpdateAPIKeyUsage(ctx context.Context, key *APIKey) error {
	return s.q.UpdateAPIKeyUsage(ctx, key)
}

func (s *Store) DeleteAPIKey(ctx context.Context, id string) error {
	return s.q.DeleteAPIKey(ctx, id)
}

func (s *Store) DeleteAPIKeysByUserID(ctx context.Context, userID string) error {
	return s.q.DeleteAPIKeysByUserID(ctx, userID)
}

func (s *Store) DeleteExpiredAPIKeys(ctx context.Context) (int64, error) {
	return s.q.DeleteExpiredAPIKeys(ctx)
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

func (a *pgAdapter) CreateAPIKey(ctx context.Context, key *APIKey) error {
	return a.q.CreateAPIKey(ctx, pgstore.CreateAPIKeyParams{
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

func (a *pgAdapter) GetAPIKeyByID(ctx context.Context, id string) (*APIKey, error) {
	row, err := a.q.GetAPIKeyByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return pgKeyToDomain(&row), nil
}

func (a *pgAdapter) GetAPIKeyByKeyPrefix(ctx context.Context, keyPrefix string) ([]*APIKey, error) {
	rows, err := a.q.GetAPIKeyByKeyPrefix(ctx, keyPrefix)
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

func (a *pgAdapter) ListAPIKeysByUserID(ctx context.Context, userID string) ([]*APIKey, error) {
	rows, err := a.q.ListAPIKeysByUserID(ctx, userID)
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

func (a *pgAdapter) UpdateAPIKey(ctx context.Context, key *APIKey) error {
	return a.q.UpdateAPIKey(ctx, pgstore.UpdateAPIKeyParams{
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

func (a *pgAdapter) UpdateAPIKeyUsage(ctx context.Context, key *APIKey) error {
	return a.q.UpdateAPIKeyUsage(ctx, pgstore.UpdateAPIKeyUsageParams{
		ID:           key.ID,
		RequestCount: key.RequestCount,
		Remaining:    toNullInt32(key.Remaining),
		LastRequest:  toNullTime(key.LastRequest),
		LastRefillAt: toNullTime(key.LastRefillAt),
		UpdatedAt:    key.UpdatedAt,
	})
}

func (a *pgAdapter) DeleteAPIKey(ctx context.Context, id string) error {
	return a.q.DeleteAPIKey(ctx, id)
}

func (a *pgAdapter) DeleteAPIKeysByUserID(ctx context.Context, userID string) error {
	return a.q.DeleteAPIKeysByUserID(ctx, userID)
}

func (a *pgAdapter) DeleteExpiredAPIKeys(ctx context.Context) (int64, error) {
	return a.q.DeleteExpiredAPIKeys(ctx, sql.NullTime{Time: time.Now(), Valid: true})
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

func (a *mysqlAdapter) CreateAPIKey(ctx context.Context, key *APIKey) error {
	return a.q.CreateAPIKey(ctx, mysqlstore.CreateAPIKeyParams{
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

func (a *mysqlAdapter) GetAPIKeyByID(ctx context.Context, id string) (*APIKey, error) {
	row, err := a.q.GetAPIKeyByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return mysqlKeyToDomain(&row), nil
}

func (a *mysqlAdapter) GetAPIKeyByKeyPrefix(ctx context.Context, keyPrefix string) ([]*APIKey, error) {
	rows, err := a.q.GetAPIKeyByKeyPrefix(ctx, keyPrefix)
	if err != nil {
		return nil, err
	}
	keys := make([]*APIKey, len(rows))
	for i, row := range rows {
		r := row
		keys[i] = mysqlKeyToDomain(&r)
	}
	return keys, nil
}

func (a *mysqlAdapter) ListAPIKeysByUserID(ctx context.Context, userID string) ([]*APIKey, error) {
	rows, err := a.q.ListAPIKeysByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	keys := make([]*APIKey, len(rows))
	for i, row := range rows {
		r := row
		keys[i] = mysqlKeyToDomain(&r)
	}
	return keys, nil
}

func (a *mysqlAdapter) UpdateAPIKey(ctx context.Context, key *APIKey) error {
	return a.q.UpdateAPIKey(ctx, mysqlstore.UpdateAPIKeyParams{
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

func (a *mysqlAdapter) UpdateAPIKeyUsage(ctx context.Context, key *APIKey) error {
	return a.q.UpdateAPIKeyUsage(ctx, mysqlstore.UpdateAPIKeyUsageParams{
		ID:           key.ID,
		RequestCount: key.RequestCount,
		Remaining:    toNullInt32(key.Remaining),
		LastRequest:  toNullTime(key.LastRequest),
		LastRefillAt: toNullTime(key.LastRefillAt),
		UpdatedAt:    key.UpdatedAt,
	})
}

func (a *mysqlAdapter) DeleteAPIKey(ctx context.Context, id string) error {
	return a.q.DeleteAPIKey(ctx, id)
}

func (a *mysqlAdapter) DeleteAPIKeysByUserID(ctx context.Context, userID string) error {
	return a.q.DeleteAPIKeysByUserID(ctx, userID)
}

func (a *mysqlAdapter) DeleteExpiredAPIKeys(ctx context.Context) (int64, error) {
	return a.q.DeleteExpiredAPIKeys(ctx, sql.NullTime{Time: time.Now(), Valid: true})
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

func (a *sqliteAdapter) CreateAPIKey(ctx context.Context, key *APIKey) error {
	return a.q.CreateAPIKey(ctx, sqlitestore.CreateAPIKeyParams{
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

func (a *sqliteAdapter) GetAPIKeyByID(ctx context.Context, id string) (*APIKey, error) {
	row, err := a.q.GetAPIKeyByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteKeyToDomain(&row), nil
}

func (a *sqliteAdapter) GetAPIKeyByKeyPrefix(ctx context.Context, keyPrefix string) ([]*APIKey, error) {
	rows, err := a.q.GetAPIKeyByKeyPrefix(ctx, keyPrefix)
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

func (a *sqliteAdapter) ListAPIKeysByUserID(ctx context.Context, userID string) ([]*APIKey, error) {
	rows, err := a.q.ListAPIKeysByUserID(ctx, userID)
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

func (a *sqliteAdapter) UpdateAPIKey(ctx context.Context, key *APIKey) error {
	return a.q.UpdateAPIKey(ctx, sqlitestore.UpdateAPIKeyParams{
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

func (a *sqliteAdapter) UpdateAPIKeyUsage(ctx context.Context, key *APIKey) error {
	return a.q.UpdateAPIKeyUsage(ctx, sqlitestore.UpdateAPIKeyUsageParams{
		ID:           key.ID,
		RequestCount: int64(key.RequestCount),
		Remaining:    toNullInt64FromInt32(key.Remaining),
		LastRequest:  timeToNullString(key.LastRequest),
		LastRefillAt: timeToNullString(key.LastRefillAt),
		UpdatedAt:    key.UpdatedAt.Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) DeleteAPIKey(ctx context.Context, id string) error {
	return a.q.DeleteAPIKey(ctx, id)
}

func (a *sqliteAdapter) DeleteAPIKeysByUserID(ctx context.Context, userID string) error {
	return a.q.DeleteAPIKeysByUserID(ctx, userID)
}

func (a *sqliteAdapter) DeleteExpiredAPIKeys(ctx context.Context) (int64, error) {
	return a.q.DeleteExpiredAPIKeys(ctx, sql.NullString{String: time.Now().Format(time.RFC3339), Valid: true})
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

// =============================================================================
// Domain conversion helpers
// =============================================================================

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

func mysqlKeyToDomain(row *mysqlstore.ApiKey) *APIKey {
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
