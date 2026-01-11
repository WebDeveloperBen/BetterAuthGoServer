package db

import (
	"database/sql"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
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

func fromNullInt64(ni sql.NullInt64) *int64 {
	if !ni.Valid {
		return nil
	}
	return &ni.Int64
}

func fromNullInt32(ni sql.NullInt32) *int32 {
	if !ni.Valid {
		return nil
	}
	return &ni.Int32
}

func fromNullInt64ToInt32(ni sql.NullInt64) *int32 {
	if !ni.Valid {
		return nil
	}
	v := int32(ni.Int64)
	return &v
}

func toNullInt64(i *int64) sql.NullInt64 {
	if i == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *i, Valid: true}
}

func toNullInt32(i *int32) sql.NullInt32 {
	if i == nil {
		return sql.NullInt32{}
	}
	return sql.NullInt32{Int32: *i, Valid: true}
}

func int32ToNullInt64(i *int32) sql.NullInt64 {
	if i == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(*i), Valid: true}
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

// parseTime is an alias for stringToTime for clearer code in adapters
func parseTime(s string) time.Time {
	return stringToTime(s)
}

// =============================================================================
// Plugin model types
// =============================================================================

// OTPToken represents an OTP token for verification
type OTPToken struct {
	ID         string
	UserID     string
	TokenHash  string
	Type       string
	Identifier *string
	ExpiresAt  time.Time
	CreatedAt  time.Time
}

// OAuthState represents OAuth flow state
type OAuthState struct {
	State      string
	Provider   string
	Verifier   *string
	RedirectTo *string
	ExpiresAt  time.Time
	CreatedAt  time.Time
}

// OAuthAccount represents stored OAuth tokens
type OAuthAccount struct {
	ID                   string
	UserID               string
	Provider             string
	ProviderAccountID    string
	AccessToken          *string
	RefreshToken         *string
	AccessTokenExpiresAt *time.Time
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// WebAuthnCredential represents a WebAuthn credential
type WebAuthnCredential struct {
	ID           string
	UserID       string
	CredentialID []byte
	PublicKey    []byte
	SignCount    int64
	Transports   *string // JSON array as string for SQLite compatibility
	CreatedAt    time.Time
	LastUsedAt   *time.Time
}

// WebAuthnSession represents a WebAuthn session
type WebAuthnSession struct {
	ID        string
	UserID    *string
	Type      string
	Data      []byte
	ExpiresAt time.Time
	CreatedAt time.Time
}

// APIKey represents an API key
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

// JWTKey represents a JWT signing key stored in the database
type JWTKey struct {
	ID            string
	Algorithm     string
	Use           string
	KeyType       string
	Status        string
	PrivateKeyEnc string
	PublicKeyJWK  string
	ActivatedAt   time.Time
	RotatedAt     *time.Time
	ExpiresAt     *time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// DeviceCode represents a device authorization code for OAuth 2.0 Device Flow
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
// PostgreSQL plugin model converters
// =============================================================================

func pgOAuthAccountToModel(a *pgstore.OauthAccount) *OAuthAccount {
	if a == nil {
		return nil
	}
	return &OAuthAccount{
		ID:                   a.ID,
		UserID:               a.UserID,
		Provider:             a.Provider,
		ProviderAccountID:    a.ProviderAccountID,
		AccessToken:          fromNullString(a.AccessToken),
		RefreshToken:         fromNullString(a.RefreshToken),
		AccessTokenExpiresAt: fromNullTime(a.AccessTokenExpiresAt),
		CreatedAt:            a.CreatedAt,
		UpdatedAt:            a.UpdatedAt,
	}
}

func pgWebAuthnCredentialToModel(c *pgstore.WebauthnCredential) *WebAuthnCredential {
	if c == nil {
		return nil
	}
	// Convert []string transports to JSON string
	var transports *string
	if len(c.Transports) > 0 {
		// Simple join for now; could use JSON encoding
		joined := ""
		for i, t := range c.Transports {
			if i > 0 {
				joined += ","
			}
			joined += t
		}
		transports = &joined
	}
	return &WebAuthnCredential{
		ID:           c.ID,
		UserID:       c.UserID,
		CredentialID: c.CredentialID,
		PublicKey:    c.PublicKey,
		SignCount:    int64(c.SignCount),
		Transports:   transports,
		CreatedAt:    c.CreatedAt,
		LastUsedAt:   fromNullTime(c.LastUsedAt),
	}
}

func pgWebAuthnSessionToModel(s *pgstore.WebauthnSession) *WebAuthnSession {
	if s == nil {
		return nil
	}
	return &WebAuthnSession{
		ID:        s.ID,
		UserID:    fromNullString(s.UserID),
		Type:      s.Type,
		Data:      s.Data,
		ExpiresAt: s.ExpiresAt,
		CreatedAt: s.CreatedAt,
	}
}

func pgAPIKeyToModel(k *pgstore.ApiKey) *APIKey {
	if k == nil {
		return nil
	}
	return &APIKey{
		ID:                  k.ID,
		Name:                fromNullString(k.Name),
		Start:               k.Start,
		Prefix:              fromNullString(k.Prefix),
		Key:                 k.Key,
		KeyPrefix:           k.KeyPrefix,
		UserID:              k.UserID,
		RateLimitEnabled:    k.RateLimitEnabled,
		RateLimitTimeWindow: fromNullInt64(k.RateLimitTimeWindow),
		RateLimitMax:        fromNullInt32(k.RateLimitMax),
		RequestCount:        k.RequestCount,
		Remaining:           fromNullInt32(k.Remaining),
		RefillInterval:      fromNullInt64(k.RefillInterval),
		RefillAmount:        fromNullInt32(k.RefillAmount),
		LastRefillAt:        fromNullTime(k.LastRefillAt),
		Enabled:             k.Enabled,
		LastRequest:         fromNullTime(k.LastRequest),
		ExpiresAt:           fromNullTime(k.ExpiresAt),
		Permissions:         fromNullString(k.Permissions),
		Metadata:            fromNullString(k.Metadata),
		CreatedAt:           k.CreatedAt,
		UpdatedAt:           k.UpdatedAt,
	}
}

func pgJWTKeyToModel(k *pgstore.JwtKey) *JWTKey {
	if k == nil {
		return nil
	}
	return &JWTKey{
		ID:            k.ID,
		Algorithm:     k.Algorithm,
		Use:           k.Use,
		KeyType:       k.Kty,
		Status:        k.Status,
		PrivateKeyEnc: k.PrivateKeyEnc,
		PublicKeyJWK:  k.PublicKeyJwk,
		ActivatedAt:   k.ActivatedAt,
		RotatedAt:     fromNullTime(k.RotatedAt),
		ExpiresAt:     fromNullTime(k.ExpiresAt),
		CreatedAt:     k.CreatedAt,
		UpdatedAt:     k.UpdatedAt,
	}
}

func pgDeviceCodeToModel(d *pgstore.DeviceCode) *DeviceCode {
	if d == nil {
		return nil
	}
	return &DeviceCode{
		ID:              d.ID,
		DeviceCode:      d.DeviceCode,
		DeviceCodeHash:  d.DeviceCodeHash,
		UserCode:        d.UserCode,
		ClientID:        fromNullString(d.ClientID),
		Scope:           fromNullString(d.Scope),
		UserID:          fromNullString(d.UserID),
		Status:          d.Status,
		PollingInterval: int(d.PollingInterval),
		LastPolledAt:    fromNullTime(d.LastPolledAt),
		ExpiresAt:       d.ExpiresAt,
		CreatedAt:       d.CreatedAt,
		UpdatedAt:       d.UpdatedAt,
	}
}

// =============================================================================
// SQLite plugin model converters
// =============================================================================

func sqliteOAuthAccountToModel(a *sqlitestore.OauthAccount) *OAuthAccount {
	if a == nil {
		return nil
	}
	return &OAuthAccount{
		ID:                   a.ID,
		UserID:               a.UserID,
		Provider:             a.Provider,
		ProviderAccountID:    a.ProviderAccountID,
		AccessToken:          fromNullString(a.AccessToken),
		RefreshToken:         fromNullString(a.RefreshToken),
		AccessTokenExpiresAt: nullStringToTime(a.AccessTokenExpiresAt),
		CreatedAt:            stringToTime(a.CreatedAt),
		UpdatedAt:            stringToTime(a.UpdatedAt),
	}
}

func sqliteWebAuthnCredentialToModel(c *sqlitestore.WebauthnCredential) *WebAuthnCredential {
	if c == nil {
		return nil
	}
	return &WebAuthnCredential{
		ID:           c.ID,
		UserID:       c.UserID,
		CredentialID: c.CredentialID,
		PublicKey:    c.PublicKey,
		SignCount:    c.SignCount,
		Transports:   fromNullString(c.Transports),
		CreatedAt:    stringToTime(c.CreatedAt),
		LastUsedAt:   nullStringToTime(c.LastUsedAt),
	}
}

func sqliteWebAuthnSessionToModel(s *sqlitestore.WebauthnSession) *WebAuthnSession {
	if s == nil {
		return nil
	}
	return &WebAuthnSession{
		ID:        s.ID,
		UserID:    fromNullString(s.UserID),
		Type:      s.Type,
		Data:      s.Data,
		ExpiresAt: stringToTime(s.ExpiresAt),
		CreatedAt: stringToTime(s.CreatedAt),
	}
}

func sqliteAPIKeyToModel(k *sqlitestore.ApiKey) *APIKey {
	if k == nil {
		return nil
	}
	return &APIKey{
		ID:                  k.ID,
		Name:                fromNullString(k.Name),
		Start:               k.Start,
		Prefix:              fromNullString(k.Prefix),
		Key:                 k.Key,
		KeyPrefix:           k.KeyPrefix,
		UserID:              k.UserID,
		RateLimitEnabled:    k.RateLimitEnabled != 0,
		RateLimitTimeWindow: fromNullInt64(k.RateLimitTimeWindow),
		RateLimitMax:        fromNullInt64ToInt32(k.RateLimitMax),
		RequestCount:        int32(k.RequestCount),
		Remaining:           fromNullInt64ToInt32(k.Remaining),
		RefillInterval:      fromNullInt64(k.RefillInterval),
		RefillAmount:        fromNullInt64ToInt32(k.RefillAmount),
		LastRefillAt:        nullStringToTime(k.LastRefillAt),
		Enabled:             k.Enabled != 0,
		LastRequest:         nullStringToTime(k.LastRequest),
		ExpiresAt:           nullStringToTime(k.ExpiresAt),
		Permissions:         fromNullString(k.Permissions),
		Metadata:            fromNullString(k.Metadata),
		CreatedAt:           stringToTime(k.CreatedAt),
		UpdatedAt:           stringToTime(k.UpdatedAt),
	}
}

func sqliteJWTKeyToModel(k *sqlitestore.JwtKey) *JWTKey {
	if k == nil {
		return nil
	}
	return &JWTKey{
		ID:            k.ID,
		Algorithm:     k.Algorithm,
		Use:           k.Use,
		KeyType:       k.Kty,
		Status:        k.Status,
		PrivateKeyEnc: k.PrivateKeyEnc,
		PublicKeyJWK:  k.PublicKeyJwk,
		ActivatedAt:   stringToTime(k.ActivatedAt),
		RotatedAt:     nullStringToTime(k.RotatedAt),
		ExpiresAt:     nullStringToTime(k.ExpiresAt),
		CreatedAt:     stringToTime(k.CreatedAt),
		UpdatedAt:     stringToTime(k.UpdatedAt),
	}
}

func sqliteDeviceCodeToModel(d *sqlitestore.DeviceCode) *DeviceCode {
	if d == nil {
		return nil
	}
	return &DeviceCode{
		ID:              d.ID,
		DeviceCode:      d.DeviceCode,
		DeviceCodeHash:  d.DeviceCodeHash,
		UserCode:        d.UserCode,
		ClientID:        fromNullString(d.ClientID),
		Scope:           fromNullString(d.Scope),
		UserID:          fromNullString(d.UserID),
		Status:          d.Status,
		PollingInterval: int(d.PollingInterval),
		LastPolledAt:    nullStringToTime(d.LastPolledAt),
		ExpiresAt:       stringToTime(d.ExpiresAt),
		CreatedAt:       stringToTime(d.CreatedAt),
		UpdatedAt:       stringToTime(d.UpdatedAt),
	}
}
