package otp

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/uptrace/bun"
)

// Store handles OTP token persistence.
type Store struct {
	db           *bun.DB
	tableCreated bool
}

// NewStore creates a new OTP store with database persistence.
func NewStore(db *bun.DB) *Store {
	return &Store{db: db}
}

// ensureTable creates the otp_tokens table if it doesn't exist.
func (s *Store) ensureTable(ctx context.Context) error {
	if s.tableCreated {
		return nil
	}

	_, err := s.db.NewCreateTable().
		Model((*OTPToken)(nil)).
		IfNotExists().
		Exec(ctx)
	if err != nil {
		return err
	}

	// Create index on token_hash for fast lookups
	_, _ = s.db.NewCreateIndex().
		Model((*OTPToken)(nil)).
		Index("idx_otp_tokens_token_hash").
		Column("token_hash").
		IfNotExists().
		Exec(ctx)

	// Create index on user_id and type for cleanup operations
	_, _ = s.db.NewCreateIndex().
		Model((*OTPToken)(nil)).
		Index("idx_otp_tokens_user_type").
		Column("user_id", "type").
		IfNotExists().
		Exec(ctx)

	s.tableCreated = true
	return nil
}

// Create stores a new OTP token.
func (s *Store) Create(ctx context.Context, token *OTPToken) error {
	if err := s.ensureTable(ctx); err != nil {
		return err
	}

	_, err := s.db.NewInsert().
		Model(token).
		Exec(ctx)
	return err
}

// GetByTokenHash retrieves a token by its hash.
func (s *Store) GetByTokenHash(ctx context.Context, tokenHash string) (*OTPToken, error) {
	if err := s.ensureTable(ctx); err != nil {
		return nil, err
	}

	token := new(OTPToken)
	err := s.db.NewSelect().
		Model(token).
		Where("token_hash = ?", tokenHash).
		Scan(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return token, nil
}

// Delete removes a token by ID.
func (s *Store) Delete(ctx context.Context, id string) error {
	if err := s.ensureTable(ctx); err != nil {
		return err
	}

	_, err := s.db.NewDelete().
		Model((*OTPToken)(nil)).
		Where("id = ?", id).
		Exec(ctx)
	return err
}

// DeleteByUserAndType removes all tokens of a specific type for a user.
func (s *Store) DeleteByUserAndType(ctx context.Context, userID string, tokenType TokenType) error {
	if err := s.ensureTable(ctx); err != nil {
		return err
	}

	_, err := s.db.NewDelete().
		Model((*OTPToken)(nil)).
		Where("user_id = ? AND type = ?", userID, tokenType).
		Exec(ctx)
	return err
}

// DeleteExpired removes all expired tokens.
func (s *Store) DeleteExpired(ctx context.Context) error {
	if err := s.ensureTable(ctx); err != nil {
		return err
	}

	_, err := s.db.NewDelete().
		Model((*OTPToken)(nil)).
		Where("expires_at < ?", time.Now()).
		Exec(ctx)
	return err
}
