package jwt

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Algorithm represents the JWT signing algorithm
type Algorithm string

const (
	AlgorithmHS256 Algorithm = "HS256"
	AlgorithmHS384 Algorithm = "HS384"
	AlgorithmHS512 Algorithm = "HS512"
	AlgorithmRS256 Algorithm = "RS256"
	AlgorithmRS384 Algorithm = "RS384"
	AlgorithmRS512 Algorithm = "RS512"
	AlgorithmES256 Algorithm = "ES256"
	AlgorithmES384 Algorithm = "ES384"
	AlgorithmES512 Algorithm = "ES512"
	AlgorithmEdDSA Algorithm = "EdDSA"
)

// KeyProvider is an interface for database-backed JWT key management.
// Implemented by both KeyManager (Bun) and KeyManagerAdapter (sqlc).
type KeyProvider interface {
	// GetActiveKey returns the current active signing key
	GetActiveKey(ctx context.Context) (*LoadedKey, error)
	// GetKeyForVerification returns a key by ID for token verification
	GetKeyForVerification(ctx context.Context, kid string) (*LoadedKey, error)
}

// Config holds JWT service configuration
type Config struct {
	// Algorithm is the signing algorithm (default: HS256)
	Algorithm Algorithm

	// Secret is the secret key for HMAC algorithms (HS256, HS384, HS512)
	Secret string

	// PrivateKey is the private key for RSA/ECDSA/EdDSA algorithms (PEM encoded)
	// Used when KeySource is KeySourceConfig
	PrivateKey []byte

	// PublicKey is the public key for RSA/ECDSA/EdDSA algorithms (PEM encoded)
	// Used when KeySource is KeySourceConfig
	PublicKey []byte

	// KeySource specifies where asymmetric keys come from (config or database)
	// Default is KeySourceConfig for backward compatibility
	KeySource KeySource

	// KeyManager handles database-backed keys (set automatically when KeySource is KeySourceDatabase)
	// Can be either *KeyManager (Bun) or *KeyManagerAdapter (sqlc)
	KeyManager KeyProvider

	// AccessTokenTTL is the lifetime of access tokens (default: 15 minutes)
	AccessTokenTTL time.Duration

	// RefreshTokenTTL is the lifetime of refresh tokens (default: 7 days)
	RefreshTokenTTL time.Duration

	// Issuer is the token issuer claim
	Issuer string

	// Audience is the token audience claim
	Audience string

	// TokenBlocklist is used to check if tokens are revoked (optional)
	TokenBlocklist TokenBlocklist

	// KeyRotationGracePeriod is how long rotated keys remain valid for verification.
	// Only used when KeySource is KeySourceDatabase.
	// Default is 24 hours.
	KeyRotationGracePeriod time.Duration

	// KeySize is the RSA key size for database-backed keys.
	// Only applies to RSA algorithms (RS256/384/512).
	// Default is 2048.
	KeySize int
}

// TokenBlocklist is an interface for checking if tokens are revoked
type TokenBlocklist interface {
	// IsRevoked checks if a token ID is revoked
	IsRevoked(ctx context.Context, jti string) (bool, error)

	// Revoke adds a token ID to the blocklist
	Revoke(ctx context.Context, jti string, expiresAt time.Time) error
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() Config {
	return Config{
		Algorithm:       AlgorithmHS256,
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
	}
}

// Service handles JWT token generation and validation
type Service struct {
	config     Config
	signingKey any
	verifyKey  any
	method     jwt.SigningMethod
	keyManager KeyProvider
}

// NewService creates a new JWT service
func NewService(cfg Config) (*Service, error) {
	if cfg.Algorithm == "" {
		cfg.Algorithm = AlgorithmHS256
	}
	if cfg.AccessTokenTTL == 0 {
		cfg.AccessTokenTTL = 15 * time.Minute
	}
	if cfg.RefreshTokenTTL == 0 {
		cfg.RefreshTokenTTL = 7 * 24 * time.Hour
	}

	s := &Service{config: cfg}

	// Configure signing method and keys
	switch cfg.Algorithm {
	case AlgorithmHS256:
		s.method = jwt.SigningMethodHS256
		if cfg.Secret == "" {
			return nil, ErrInvalidSigningKey
		}
		s.signingKey = []byte(cfg.Secret)
		s.verifyKey = []byte(cfg.Secret)

	case AlgorithmHS384:
		s.method = jwt.SigningMethodHS384
		if cfg.Secret == "" {
			return nil, ErrInvalidSigningKey
		}
		s.signingKey = []byte(cfg.Secret)
		s.verifyKey = []byte(cfg.Secret)

	case AlgorithmHS512:
		s.method = jwt.SigningMethodHS512
		if cfg.Secret == "" {
			return nil, ErrInvalidSigningKey
		}
		s.signingKey = []byte(cfg.Secret)
		s.verifyKey = []byte(cfg.Secret)

	case AlgorithmRS256:
		s.method = jwt.SigningMethodRS256
		if err := s.configureAsymmetricKeys(cfg); err != nil {
			return nil, err
		}

	case AlgorithmRS384:
		s.method = jwt.SigningMethodRS384
		if err := s.configureAsymmetricKeys(cfg); err != nil {
			return nil, err
		}

	case AlgorithmRS512:
		s.method = jwt.SigningMethodRS512
		if err := s.configureAsymmetricKeys(cfg); err != nil {
			return nil, err
		}

	case AlgorithmES256:
		s.method = jwt.SigningMethodES256
		if err := s.configureAsymmetricKeys(cfg); err != nil {
			return nil, err
		}

	case AlgorithmES384:
		s.method = jwt.SigningMethodES384
		if err := s.configureAsymmetricKeys(cfg); err != nil {
			return nil, err
		}

	case AlgorithmES512:
		s.method = jwt.SigningMethodES512
		if err := s.configureAsymmetricKeys(cfg); err != nil {
			return nil, err
		}

	case AlgorithmEdDSA:
		s.method = jwt.SigningMethodEdDSA
		if err := s.configureAsymmetricKeys(cfg); err != nil {
			return nil, err
		}

	default:
		return nil, ErrUnsupportedAlgorithm
	}

	return s, nil
}

// configureAsymmetricKeys sets up signing/verification keys for asymmetric algorithms.
// Supports both config-provided keys and database-backed keys with KeyManager.
func (s *Service) configureAsymmetricKeys(cfg Config) error {
	// If using database-backed keys, just store the KeyManager reference
	if cfg.KeySource == KeySourceDatabase {
		if cfg.KeyManager == nil {
			return ErrDatabaseRequired
		}
		s.keyManager = cfg.KeyManager
		// Keys will be loaded on-demand during signing/verification
		return nil
	}

	// Using config-provided keys (KeySourceConfig or default)
	if len(cfg.PrivateKey) == 0 || len(cfg.PublicKey) == 0 {
		return ErrInvalidSigningKey
	}

	// Parse private key
	privateKey, err := parsePrivateKeyPEM(cfg.PrivateKey, cfg.Algorithm)
	if err != nil {
		return err
	}
	s.signingKey = privateKey

	// Parse public key
	publicKey, err := parsePublicKeyPEM(cfg.PublicKey, cfg.Algorithm)
	if err != nil {
		return err
	}
	s.verifyKey = publicKey

	return nil
}

// parsePrivateKeyPEM parses a PEM-encoded private key for the given algorithm.
func parsePrivateKeyPEM(pemData []byte, alg Algorithm) (any, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, ErrInvalidSigningKey
	}

	switch alg {
	case AlgorithmRS256, AlgorithmRS384, AlgorithmRS512:
		// Try PKCS1 first, then PKCS8
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			// Try PKCS8
			pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, ErrInvalidSigningKey
			}
			return pkcs8Key, nil
		}
		return key, nil

	case AlgorithmES256, AlgorithmES384, AlgorithmES512:
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			// Try PKCS8
			pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, ErrInvalidSigningKey
			}
			return pkcs8Key, nil
		}
		return key, nil

	case AlgorithmEdDSA:
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrInvalidSigningKey
		}
		return key, nil

	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

// parsePublicKeyPEM parses a PEM-encoded public key for the given algorithm.
func parsePublicKeyPEM(pemData []byte, alg Algorithm) (any, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, ErrInvalidSigningKey
	}

	// Try PKIX format (most common for public keys)
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		// For RSA, try parsing as PKCS1
		if alg == AlgorithmRS256 || alg == AlgorithmRS384 || alg == AlgorithmRS512 {
			rsaKey, rsaErr := x509.ParsePKCS1PublicKey(block.Bytes)
			if rsaErr != nil {
				return nil, ErrInvalidSigningKey
			}
			return rsaKey, nil
		}
		return nil, ErrInvalidSigningKey
	}
	return key, nil
}

// TokenPair contains an access token and refresh token
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// UserInfo contains user information for token generation
type UserInfo struct {
	ID            string
	Email         string
	Name          string
	EmailVerified bool
	// ActorID is the ID of the user acting on behalf of this user (for impersonation).
	// If set, the "act" claim will be included in generated tokens per RFC 8693.
	ActorID *string
}

// GenerateTokenPair generates a new access/refresh token pair.
// Context is required for database-backed key operations.
func (s *Service) GenerateTokenPair(ctx context.Context, user UserInfo, sessionID string) (*TokenPair, error) {
	accessToken, err := s.generateAccessToken(ctx, user, sessionID)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.generateRefreshToken(ctx, user, sessionID)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.config.AccessTokenTTL.Seconds()),
	}, nil
}

// generateAccessToken generates a new access token
func (s *Service) generateAccessToken(ctx context.Context, user UserInfo, sessionID string) (string, error) {
	claims := NewAccessClaims(
		user.ID,
		sessionID,
		user.Email,
		user.Name,
		user.EmailVerified,
		s.config.Issuer,
		s.config.Audience,
		s.config.AccessTokenTTL,
		user.ActorID,
	)

	token := jwt.NewWithClaims(s.method, claims)

	// If using KeyManager, get active key and add kid header
	if s.keyManager != nil {
		key, err := s.keyManager.GetActiveKey(ctx)
		if err != nil {
			return "", err
		}
		token.Header["kid"] = key.ID
		return token.SignedString(key.PrivateKey)
	}

	return token.SignedString(s.signingKey)
}

// generateRefreshToken generates a new refresh token
func (s *Service) generateRefreshToken(ctx context.Context, user UserInfo, sessionID string) (string, error) {
	claims := NewRefreshClaims(
		user.ID,
		sessionID,
		s.config.Issuer,
		s.config.Audience,
		s.config.RefreshTokenTTL,
		user.ActorID,
	)

	token := jwt.NewWithClaims(s.method, claims)

	// If using KeyManager, get active key and add kid header
	if s.keyManager != nil {
		key, err := s.keyManager.GetActiveKey(ctx)
		if err != nil {
			return "", err
		}
		token.Header["kid"] = key.ID
		return token.SignedString(key.PrivateKey)
	}

	return token.SignedString(s.signingKey)
}

// ValidateToken validates a token and returns the claims
func (s *Service) ValidateToken(ctx context.Context, tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (any, error) {
		// Validate signing method
		if token.Method.Alg() != string(s.config.Algorithm) {
			return nil, ErrUnsupportedAlgorithm
		}

		// If using KeyManager, lookup key by kid
		if s.keyManager != nil {
			kid, ok := token.Header["kid"].(string)
			if !ok || kid == "" {
				return nil, ErrKeyNotFound
			}
			key, err := s.keyManager.GetKeyForVerification(ctx, kid)
			if err != nil {
				return nil, err
			}
			return key.PublicKey, nil
		}

		return s.verifyKey, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	// Check blocklist if configured
	if s.config.TokenBlocklist != nil {
		revoked, err := s.config.TokenBlocklist.IsRevoked(ctx, claims.ID)
		if err != nil {
			return nil, err
		}
		if revoked {
			return nil, ErrTokenRevoked
		}
	}

	return claims, nil
}

// ValidateAccessToken validates an access token
func (s *Service) ValidateAccessToken(ctx context.Context, tokenString string) (*Claims, error) {
	claims, err := s.ValidateToken(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != TokenTypeAccess {
		return nil, ErrInvalidTokenType
	}

	return claims, nil
}

// ValidateRefreshToken validates a refresh token
func (s *Service) ValidateRefreshToken(ctx context.Context, tokenString string) (*Claims, error) {
	claims, err := s.ValidateToken(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != TokenTypeRefresh {
		return nil, ErrInvalidTokenType
	}

	return claims, nil
}

// RefreshTokens refreshes tokens using a valid refresh token
func (s *Service) RefreshTokens(ctx context.Context, refreshToken string, user UserInfo) (*TokenPair, error) {
	claims, err := s.ValidateRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, err
	}

	// Revoke the old refresh token if blocklist is configured
	if s.config.TokenBlocklist != nil && claims.ExpiresAt != nil {
		if err := s.config.TokenBlocklist.Revoke(ctx, claims.ID, claims.ExpiresAt.Time); err != nil {
			return nil, err
		}
	}

	// Preserve actor claim from the original token (for impersonation sessions)
	if claims.Act != nil && user.ActorID == nil {
		user.ActorID = &claims.Act.Sub
	}

	// Generate new token pair
	return s.GenerateTokenPair(ctx, user, claims.SessionID)
}

// RevokeToken revokes a token by its JTI
func (s *Service) RevokeToken(ctx context.Context, tokenString string) error {
	if s.config.TokenBlocklist == nil {
		return nil // No blocklist configured, nothing to do
	}

	claims, err := s.ValidateToken(ctx, tokenString)
	if err != nil {
		// If token is already invalid, consider it revoked
		if errors.Is(err, ErrExpiredToken) || errors.Is(err, ErrTokenRevoked) {
			return nil
		}
		return err
	}

	if claims.ExpiresAt == nil {
		return nil
	}

	return s.config.TokenBlocklist.Revoke(ctx, claims.ID, claims.ExpiresAt.Time)
}

// Config returns the service configuration
func (s *Service) Config() Config {
	return s.config
}

// KeyManager returns the key manager (nil if not using database-backed keys)
func (s *Service) KeyManager() KeyProvider {
	return s.keyManager
}
