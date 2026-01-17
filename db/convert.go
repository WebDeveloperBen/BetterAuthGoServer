package db

import (
	"database/sql"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/db/mysqlstore"
	"github.com/webdeveloperben/BetterAuthGoServer/db/pgstore"
	"github.com/webdeveloperben/BetterAuthGoServer/db/sqlitestore"
)

// =============================================================================
// Null type helpers
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

func boolToInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func intToBool(i int64) bool {
	return i != 0
}

func timeToString(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.Format(time.RFC3339)
	return &s
}

func stringToTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

func nullStringToTime(ns sql.NullString) *time.Time {
	if !ns.Valid {
		return nil
	}
	t, err := time.Parse(time.RFC3339, ns.String)
	if err != nil {
		return nil
	}
	return &t
}

// =============================================================================
// PostgreSQL model converters
// =============================================================================

func pgUserToModel(u *pgstore.User) *models.User {
	if u == nil {
		return nil
	}
	return &models.User{
		ID:            u.ID,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Name:          u.Name,
		Image:         fromNullString(u.Image),
		Banned:        u.Banned,
		BannedAt:      fromNullTime(u.BannedAt),
		BanReason:     fromNullString(u.BanReason),
		Role:          u.Role,
		CreatedAt:     u.CreatedAt,
		UpdatedAt:     u.UpdatedAt,
	}
}

func pgAccountToModel(a *pgstore.Account) *models.Account {
	if a == nil {
		return nil
	}
	return &models.Account{
		ID:                a.ID,
		UserID:            a.UserID,
		Provider:          models.ProviderType(a.Provider),
		ProviderAccountID: fromNullString(a.ProviderAccountID),
		PasswordHash:      fromNullString(a.PasswordHash),
		CreatedAt:         a.CreatedAt,
		UpdatedAt:         a.UpdatedAt,
	}
}

func pgSessionToModel(s *pgstore.Session) *models.Session {
	if s == nil {
		return nil
	}
	return &models.Session{
		ID:             s.ID,
		UserID:         s.UserID,
		TokenHash:      s.TokenHash,
		IPAddress:      fromNullString(s.IpAddress),
		UserAgent:      fromNullString(s.UserAgent),
		CreatedAt:      s.CreatedAt,
		ExpiresAt:      s.ExpiresAt,
		LastUsed:       s.LastUsed,
		ImpersonatedBy: fromNullString(s.ImpersonatedBy),
	}
}

func pgVerificationToModel(v *pgstore.Verification) *models.Verification {
	if v == nil {
		return nil
	}
	return &models.Verification{
		ID:         v.ID,
		UserID:     v.UserID,
		TokenHash:  v.TokenHash,
		Type:       models.VerificationType(v.Type),
		Identifier: fromNullString(v.Identifier),
		ExpiresAt:  v.ExpiresAt,
		CreatedAt:  v.CreatedAt,
	}
}

// =============================================================================
// SQLite model converters
// =============================================================================

func sqliteUserToModel(u *sqlitestore.User) *models.User {
	if u == nil {
		return nil
	}
	return &models.User{
		ID:            u.ID,
		Email:         u.Email,
		EmailVerified: intToBool(u.EmailVerified),
		Name:          u.Name,
		Image:         fromNullString(u.Image),
		Banned:        intToBool(u.Banned),
		BannedAt:      nullStringToTime(u.BannedAt),
		BanReason:     fromNullString(u.BanReason),
		Role:          u.Role,
		CreatedAt:     stringToTime(u.CreatedAt),
		UpdatedAt:     stringToTime(u.UpdatedAt),
	}
}

func sqliteAccountToModel(a *sqlitestore.Account) *models.Account {
	if a == nil {
		return nil
	}
	return &models.Account{
		ID:                a.ID,
		UserID:            a.UserID,
		Provider:          models.ProviderType(a.Provider),
		ProviderAccountID: fromNullString(a.ProviderAccountID),
		PasswordHash:      fromNullString(a.PasswordHash),
		CreatedAt:         stringToTime(a.CreatedAt),
		UpdatedAt:         stringToTime(a.UpdatedAt),
	}
}

func sqliteSessionToModel(s *sqlitestore.Session) *models.Session {
	if s == nil {
		return nil
	}
	return &models.Session{
		ID:             s.ID,
		UserID:         s.UserID,
		TokenHash:      s.TokenHash,
		IPAddress:      fromNullString(s.IpAddress),
		UserAgent:      fromNullString(s.UserAgent),
		CreatedAt:      stringToTime(s.CreatedAt),
		ExpiresAt:      stringToTime(s.ExpiresAt),
		LastUsed:       stringToTime(s.LastUsed),
		ImpersonatedBy: fromNullString(s.ImpersonatedBy),
	}
}

func sqliteVerificationToModel(v *sqlitestore.Verification) *models.Verification {
	if v == nil {
		return nil
	}
	return &models.Verification{
		ID:         v.ID,
		UserID:     v.UserID,
		TokenHash:  v.TokenHash,
		Type:       models.VerificationType(v.Type),
		Identifier: fromNullString(v.Identifier),
		ExpiresAt:  stringToTime(v.ExpiresAt),
		CreatedAt:  stringToTime(v.CreatedAt),
	}
}

// =============================================================================
// MySQL to Model conversions
// =============================================================================

func mysqlUserToModel(u *mysqlstore.User) *models.User {
	if u == nil {
		return nil
	}
	return &models.User{
		ID:            u.ID,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Name:          u.Name,
		Image:         fromNullString(u.Image),
		Banned:        u.Banned,
		BannedAt:      fromNullTime(u.BannedAt),
		BanReason:     fromNullString(u.BanReason),
		Role:          u.Role,
		CreatedAt:     u.CreatedAt,
		UpdatedAt:     u.UpdatedAt,
	}
}

func mysqlAccountToModel(a *mysqlstore.Account) *models.Account {
	if a == nil {
		return nil
	}
	return &models.Account{
		ID:                a.ID,
		UserID:            a.UserID,
		Provider:          models.ProviderType(a.Provider),
		ProviderAccountID: fromNullString(a.ProviderAccountID),
		PasswordHash:      fromNullString(a.PasswordHash),
		CreatedAt:         a.CreatedAt,
		UpdatedAt:         a.UpdatedAt,
	}
}

func mysqlSessionToModel(s *mysqlstore.Session) *models.Session {
	if s == nil {
		return nil
	}
	return &models.Session{
		ID:             s.ID,
		UserID:         s.UserID,
		TokenHash:      s.TokenHash,
		IPAddress:      fromNullString(s.IpAddress),
		UserAgent:      fromNullString(s.UserAgent),
		CreatedAt:      s.CreatedAt,
		ExpiresAt:      s.ExpiresAt,
		LastUsed:       s.LastUsed,
		ImpersonatedBy: fromNullString(s.ImpersonatedBy),
	}
}

func mysqlVerificationToModel(v *mysqlstore.Verification) *models.Verification {
	if v == nil {
		return nil
	}
	return &models.Verification{
		ID:         v.ID,
		UserID:     v.UserID,
		TokenHash:  v.TokenHash,
		Type:       models.VerificationType(v.Type),
		Identifier: fromNullString(v.Identifier),
		ExpiresAt:  v.ExpiresAt,
		CreatedAt:  v.CreatedAt,
	}
}
