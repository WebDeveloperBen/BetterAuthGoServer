package db

import (
	"context"
	"database/sql"
	"time"

	"github.com/uptrace/bun"
	"github.com/webdeveloperben/BetterAuthGoServer/auth"
)

// Session model for Bun
type Session struct {
	bun.BaseModel `bun:"table:sessions,alias:s"`

	ID        string    `bun:"id,pk"`
	UserID    string    `bun:"user_id,notnull"`
	TokenHash string    `bun:"token_hash,notnull,unique"`
	IPAddress *string   `bun:"ip_address"`
	UserAgent *string   `bun:"user_agent"`
	CreatedAt time.Time `bun:"created_at,notnull,default:current_timestamp"`
	ExpiresAt time.Time `bun:"expires_at,notnull"`
	LastUsed  time.Time `bun:"last_used,notnull,default:current_timestamp"`

	// Relations
	User *User `bun:"rel:belongs-to,join:user_id=id"`
}

func toAuthSession(s *Session) *auth.Session {
	if s == nil {
		return nil
	}
	return &auth.Session{
		ID:        s.ID,
		UserID:    s.UserID,
		TokenHash: s.TokenHash,
		IPAddress: s.IPAddress,
		UserAgent: s.UserAgent,
		CreatedAt: s.CreatedAt,
		ExpiresAt: s.ExpiresAt,
		LastUsed:  s.LastUsed,
	}
}

func toBunSession(s *auth.Session) *Session {
	if s == nil {
		return nil
	}
	return &Session{
		ID:        s.ID,
		UserID:    s.UserID,
		TokenHash: s.TokenHash,
		IPAddress: s.IPAddress,
		UserAgent: s.UserAgent,
		CreatedAt: s.CreatedAt,
		ExpiresAt: s.ExpiresAt,
		LastUsed:  s.LastUsed,
	}
}

func (s *Store) CreateSession(ctx context.Context, session *auth.Session) error {
	bunSession := toBunSession(session)
	_, err := s.db.NewInsert().Model(bunSession).Exec(ctx)
	return err
}

func (s *Store) GetSessionByID(ctx context.Context, id string) (*auth.Session, error) {
	session := new(Session)
	err := s.db.NewSelect().Model(session).Where("id = ?", id).Scan(ctx)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return toAuthSession(session), nil
}

func (s *Store) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*auth.Session, error) {
	session := new(Session)
	err := s.db.NewSelect().Model(session).Where("token_hash = ?", tokenHash).Scan(ctx)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return toAuthSession(session), nil
}

func (s *Store) ListSessionsByUserID(ctx context.Context, userID string) ([]*auth.Session, error) {
	var sessions []Session
	err := s.db.NewSelect().Model(&sessions).
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Scan(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]*auth.Session, len(sessions))
	for i := range sessions {
		result[i] = toAuthSession(&sessions[i])
	}
	return result, nil
}

func (s *Store) UpdateSessionLastUsed(ctx context.Context, id string) error {
	_, err := s.db.NewUpdate().
		Model((*Session)(nil)).
		Set("last_used = ?", time.Now()).
		Where("id = ?", id).
		Exec(ctx)
	return err
}

func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, err := s.db.NewDelete().Model((*Session)(nil)).Where("id = ?", id).Exec(ctx)
	return err
}

func (s *Store) DeleteSessionsByUserID(ctx context.Context, userID string) error {
	_, err := s.db.NewDelete().Model((*Session)(nil)).Where("user_id = ?", userID).Exec(ctx)
	return err
}

func (s *Store) DeleteExpiredSessions(ctx context.Context) error {
	_, err := s.db.NewDelete().Model((*Session)(nil)).Where("expires_at < ?", time.Now()).Exec(ctx)
	return err
}
