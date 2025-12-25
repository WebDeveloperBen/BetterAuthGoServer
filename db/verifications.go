package db

import (
	"context"
	"database/sql"
	"time"

	"github.com/uptrace/bun"
	"github.com/webdeveloperben/BetterAuthGoServer/auth"
)

// Verification model for Bun
type Verification struct {
	bun.BaseModel `bun:"table:verifications,alias:v"`

	ID         string    `bun:"id,pk"`
	UserID     string    `bun:"user_id,notnull"`
	TokenHash  string    `bun:"token_hash,notnull,unique"`
	Type       string    `bun:"type,notnull"`
	Identifier *string   `bun:"identifier"`
	ExpiresAt  time.Time `bun:"expires_at,notnull"`
	CreatedAt  time.Time `bun:"created_at,notnull,default:current_timestamp"`

	// Relations
	User *User `bun:"rel:belongs-to,join:user_id=id"`
}

func toAuthVerification(v *Verification) *auth.Verification {
	if v == nil {
		return nil
	}
	return &auth.Verification{
		ID:         v.ID,
		UserID:     v.UserID,
		TokenHash:  v.TokenHash,
		Type:       auth.VerificationType(v.Type),
		Identifier: v.Identifier,
		ExpiresAt:  v.ExpiresAt,
		CreatedAt:  v.CreatedAt,
	}
}

func toBunVerification(v *auth.Verification) *Verification {
	if v == nil {
		return nil
	}
	return &Verification{
		ID:         v.ID,
		UserID:     v.UserID,
		TokenHash:  v.TokenHash,
		Type:       string(v.Type),
		Identifier: v.Identifier,
		ExpiresAt:  v.ExpiresAt,
		CreatedAt:  v.CreatedAt,
	}
}

func (s *Store) CreateVerification(ctx context.Context, v *auth.Verification) error {
	bunVerification := toBunVerification(v)
	_, err := s.db.NewInsert().Model(bunVerification).Exec(ctx)
	return err
}

func (s *Store) GetVerificationByTokenHash(ctx context.Context, tokenHash string) (*auth.Verification, error) {
	verification := new(Verification)
	err := s.db.NewSelect().Model(verification).Where("token_hash = ?", tokenHash).Scan(ctx)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return toAuthVerification(verification), nil
}

func (s *Store) DeleteVerification(ctx context.Context, id string) error {
	_, err := s.db.NewDelete().Model((*Verification)(nil)).Where("id = ?", id).Exec(ctx)
	return err
}

func (s *Store) DeleteVerificationsByUserIDAndType(ctx context.Context, userID string, vType auth.VerificationType) error {
	_, err := s.db.NewDelete().Model((*Verification)(nil)).
		Where("user_id = ?", userID).
		Where("type = ?", string(vType)).
		Exec(ctx)
	return err
}

func (s *Store) DeleteExpiredVerifications(ctx context.Context) error {
	_, err := s.db.NewDelete().Model((*Verification)(nil)).Where("expires_at < ?", time.Now()).Exec(ctx)
	return err
}
