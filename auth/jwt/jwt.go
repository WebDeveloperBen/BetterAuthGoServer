package jwt

import (
	"context"
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
)

// Config holds JWT service configuration
type Config struct {
	// Algorithm is the signing algorithm (default: HS256)
	Algorithm Algorithm

	// Secret is the secret key for HMAC algorithms (HS256, HS384, HS512)
	Secret string

	// PrivateKey is the private key for RSA/ECDSA algorithms (PEM encoded)
	PrivateKey []byte

	// PublicKey is the public key for RSA/ECDSA algorithms (PEM encoded)
	PublicKey []byte

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

	case AlgorithmRS256, AlgorithmRS384, AlgorithmRS512:
		return nil, errors.New("RSA algorithms not yet implemented")

	case AlgorithmES256, AlgorithmES384, AlgorithmES512:
		return nil, errors.New("ECDSA algorithms not yet implemented")

	default:
		return nil, ErrUnsupportedAlgorithm
	}

	return s, nil
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
}

// GenerateTokenPair generates a new access/refresh token pair
func (s *Service) GenerateTokenPair(user UserInfo, sessionID string) (*TokenPair, error) {
	accessToken, err := s.generateAccessToken(user, sessionID)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.generateRefreshToken(user.ID, sessionID)
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
func (s *Service) generateAccessToken(user UserInfo, sessionID string) (string, error) {
	claims := NewAccessClaims(
		user.ID,
		sessionID,
		user.Email,
		user.Name,
		user.EmailVerified,
		s.config.Issuer,
		s.config.Audience,
		s.config.AccessTokenTTL,
	)

	token := jwt.NewWithClaims(s.method, claims)
	return token.SignedString(s.signingKey)
}

// generateRefreshToken generates a new refresh token
func (s *Service) generateRefreshToken(userID, sessionID string) (string, error) {
	claims := NewRefreshClaims(
		userID,
		sessionID,
		s.config.Issuer,
		s.config.Audience,
		s.config.RefreshTokenTTL,
	)

	token := jwt.NewWithClaims(s.method, claims)
	return token.SignedString(s.signingKey)
}

// ValidateToken validates a token and returns the claims
func (s *Service) ValidateToken(ctx context.Context, tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (any, error) {
		// Validate signing method
		if token.Method.Alg() != string(s.config.Algorithm) {
			return nil, ErrUnsupportedAlgorithm
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

	// Generate new token pair
	return s.GenerateTokenPair(user, claims.SessionID)
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
