package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/token"
)

// KeyManager handles cryptographic key lifecycle for asymmetric JWT algorithms.
// It provides key generation, storage with encryption, caching, and rotation.
type KeyManager struct {
	db          *bun.DB
	encryptor   *token.Encryptor
	algorithm   Algorithm
	keySize     int           // RSA key size (default 2048)
	curve       elliptic.Curve
	gracePeriod time.Duration // How long rotated keys remain valid
	logger      *slog.Logger

	// In-memory cache
	mu          sync.RWMutex
	activeKey   *LoadedKey
	allKeys     map[string]*LoadedKey
	lastRefresh time.Time
}

// LoadedKey represents a decrypted key ready for use
type LoadedKey struct {
	ID          string
	Algorithm   string
	Status      string
	PrivateKey  crypto.PrivateKey
	PublicKey   crypto.PublicKey
	ActivatedAt time.Time
	ExpiresAt   *time.Time
}

// KeyManagerOption configures a KeyManager
type KeyManagerOption func(*KeyManager)

// WithKeyManagerGracePeriod sets the grace period for rotated keys
func WithKeyManagerGracePeriod(d time.Duration) KeyManagerOption {
	return func(km *KeyManager) {
		km.gracePeriod = d
	}
}

// WithKeyManagerKeySize sets the RSA key size
func WithKeyManagerKeySize(size int) KeyManagerOption {
	return func(km *KeyManager) {
		km.keySize = size
	}
}

// WithKeyManagerCurve sets the elliptic curve for ECDSA
func WithKeyManagerCurve(curve elliptic.Curve) KeyManagerOption {
	return func(km *KeyManager) {
		km.curve = curve
	}
}

// WithKeyManagerLogger sets the logger
func WithKeyManagerLogger(logger *slog.Logger) KeyManagerOption {
	return func(km *KeyManager) {
		km.logger = logger
	}
}

// NewKeyManager creates a new KeyManager
func NewKeyManager(db *bun.DB, encryptor *token.Encryptor, alg Algorithm, opts ...KeyManagerOption) *KeyManager {
	km := &KeyManager{
		db:          db,
		encryptor:   encryptor,
		algorithm:   alg,
		keySize:     2048,
		curve:       elliptic.P256(),
		gracePeriod: 24 * time.Hour,
		allKeys:     make(map[string]*LoadedKey),
		logger:      slog.Default(),
	}
	for _, opt := range opts {
		opt(km)
	}
	return km
}

// GenerateKey generates a new key pair and stores it in the database.
// If there's an existing active key, it's moved to rotating status.
func (km *KeyManager) GenerateKey(ctx context.Context) (*JWK, error) {
	var privateKey crypto.PrivateKey
	var publicKey crypto.PublicKey
	var keyType string

	switch km.algorithm {
	case AlgorithmRS256, AlgorithmRS384, AlgorithmRS512:
		key, err := rsa.GenerateKey(rand.Reader, km.keySize)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrKeyGeneration, err)
		}
		privateKey = key
		publicKey = &key.PublicKey
		keyType = KeyTypeRSA

	case AlgorithmES256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrKeyGeneration, err)
		}
		privateKey = key
		publicKey = &key.PublicKey
		keyType = KeyTypeEC

	case AlgorithmES384:
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrKeyGeneration, err)
		}
		privateKey = key
		publicKey = &key.PublicKey
		keyType = KeyTypeEC

	case AlgorithmES512:
		key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrKeyGeneration, err)
		}
		privateKey = key
		publicKey = &key.PublicKey
		keyType = KeyTypeEC

	case AlgorithmEdDSA:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrKeyGeneration, err)
		}
		privateKey = priv
		publicKey = pub
		keyType = KeyTypeOKP

	default:
		return nil, ErrUnsupportedAlgorithm
	}

	// Serialize and encrypt private key
	privateKeyPEM, err := km.marshalPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	encryptedPrivate, err := km.encryptor.Encrypt(string(privateKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyEncryption, err)
	}

	// Generate public key JWK
	publicKeyJWK, err := km.publicKeyToJWK(publicKey, keyType)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	jwk := &JWK{
		ID:            uuid.New().String(),
		Algorithm:     string(km.algorithm),
		Use:           KeyUseSignature,
		KeyType:       keyType,
		Status:        KeyStatusActive,
		PrivateKeyEnc: encryptedPrivate,
		PublicKeyJWK:  publicKeyJWK,
		ActivatedAt:   now,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	// Start transaction
	tx, err := km.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	// Move any existing active key to rotating status
	expiresAt := now.Add(km.gracePeriod)
	_, err = tx.NewUpdate().
		Model((*JWK)(nil)).
		Set("status = ?", KeyStatusRotating).
		Set("rotated_at = ?", now).
		Set("expires_at = ?", expiresAt).
		Set("updated_at = ?", now).
		Where("algorithm = ? AND status = ?", km.algorithm, KeyStatusActive).
		Exec(ctx)
	if err != nil {
		return nil, err
	}

	// Insert new key
	_, err = tx.NewInsert().Model(jwk).Exec(ctx)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	// Invalidate cache
	km.mu.Lock()
	km.activeKey = nil
	km.lastRefresh = time.Time{}
	km.mu.Unlock()

	km.logger.Info("generated new JWT signing key",
		"kid", jwk.ID,
		"algorithm", jwk.Algorithm,
		"key_type", jwk.KeyType,
	)

	return jwk, nil
}

// GetActiveKey returns the current active signing key.
// Uses in-memory caching with 1-minute refresh interval.
func (km *KeyManager) GetActiveKey(ctx context.Context) (*LoadedKey, error) {
	km.mu.RLock()
	if km.activeKey != nil && time.Since(km.lastRefresh) < time.Minute {
		key := km.activeKey
		km.mu.RUnlock()
		return key, nil
	}
	km.mu.RUnlock()

	return km.refreshAndGetActive(ctx)
}

// GetKeyForVerification returns a key by ID for token verification.
// Supports both active and rotating (grace period) keys.
func (km *KeyManager) GetKeyForVerification(ctx context.Context, kid string) (*LoadedKey, error) {
	// Check cache first
	km.mu.RLock()
	if key, ok := km.allKeys[kid]; ok {
		km.mu.RUnlock()
		// Check if key is still valid
		if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
			return nil, ErrKeyExpired
		}
		return key, nil
	}
	km.mu.RUnlock()

	// Load from database
	return km.loadKey(ctx, kid)
}

// GetJWKS returns all public keys in JWKS format (active + rotating keys).
func (km *KeyManager) GetJWKS(ctx context.Context) (*JWKS, error) {
	var keys []JWK
	err := km.db.NewSelect().
		Model(&keys).
		Where("algorithm = ?", km.algorithm).
		Where("status IN (?, ?)", KeyStatusActive, KeyStatusRotating).
		Where("expires_at IS NULL OR expires_at > ?", time.Now()).
		Order("activated_at DESC").
		Scan(ctx)
	if err != nil {
		return nil, err
	}

	jwks := &JWKS{Keys: make([]JWKPublic, 0, len(keys))}
	for _, key := range keys {
		var publicKey JWKPublic
		if err := json.Unmarshal([]byte(key.PublicKeyJWK), &publicKey); err != nil {
			km.logger.Warn("failed to unmarshal public key JWK", "kid", key.ID, "error", err)
			continue
		}
		publicKey.Kid = key.ID
		publicKey.Alg = key.Algorithm
		publicKey.Use = key.Use
		jwks.Keys = append(jwks.Keys, publicKey)
	}

	return jwks, nil
}

// RotateKey creates a new key and puts the current one in grace period.
// This is an alias for GenerateKey.
func (km *KeyManager) RotateKey(ctx context.Context) (*JWK, error) {
	return km.GenerateKey(ctx)
}

// CleanupExpiredKeys marks expired rotating keys as retired.
func (km *KeyManager) CleanupExpiredKeys(ctx context.Context) (int64, error) {
	result, err := km.db.NewUpdate().
		Model((*JWK)(nil)).
		Set("status = ?", KeyStatusRetired).
		Set("updated_at = ?", time.Now()).
		Where("status = ? AND expires_at < ?", KeyStatusRotating, time.Now()).
		Exec(ctx)
	if err != nil {
		return 0, err
	}

	affected, _ := result.RowsAffected()
	if affected > 0 {
		km.logger.Info("cleaned up expired JWT keys", "count", affected)
	}

	return affected, nil
}

// EnsureActiveKey ensures there's an active key, generating one if needed.
func (km *KeyManager) EnsureActiveKey(ctx context.Context) (*JWK, error) {
	var key JWK
	err := km.db.NewSelect().
		Model(&key).
		Where("algorithm = ? AND status = ?", km.algorithm, KeyStatusActive).
		Limit(1).
		Scan(ctx)
	if err == nil {
		return &key, nil
	}

	// No active key found, generate one
	return km.GenerateKey(ctx)
}

// refreshAndGetActive refreshes the cache and returns the active key.
func (km *KeyManager) refreshAndGetActive(ctx context.Context) (*LoadedKey, error) {
	km.mu.Lock()
	defer km.mu.Unlock()

	// Double-check after acquiring lock
	if km.activeKey != nil && time.Since(km.lastRefresh) < time.Minute {
		return km.activeKey, nil
	}

	var jwk JWK
	err := km.db.NewSelect().
		Model(&jwk).
		Where("algorithm = ? AND status = ?", km.algorithm, KeyStatusActive).
		Limit(1).
		Scan(ctx)
	if err != nil {
		return nil, ErrNoActiveKey
	}

	loaded, err := km.decryptAndLoadKey(&jwk)
	if err != nil {
		return nil, err
	}

	km.activeKey = loaded
	km.allKeys[loaded.ID] = loaded
	km.lastRefresh = time.Now()

	return loaded, nil
}

// loadKey loads a key from the database by ID.
func (km *KeyManager) loadKey(ctx context.Context, kid string) (*LoadedKey, error) {
	var jwk JWK
	err := km.db.NewSelect().
		Model(&jwk).
		Where("id = ?", kid).
		Where("status IN (?, ?)", KeyStatusActive, KeyStatusRotating).
		Scan(ctx)
	if err != nil {
		return nil, ErrKeyNotFound
	}

	// Check expiration
	if jwk.ExpiresAt != nil && time.Now().After(*jwk.ExpiresAt) {
		return nil, ErrKeyExpired
	}

	loaded, err := km.decryptAndLoadKey(&jwk)
	if err != nil {
		return nil, err
	}

	// Cache it
	km.mu.Lock()
	km.allKeys[loaded.ID] = loaded
	km.mu.Unlock()

	return loaded, nil
}

// decryptAndLoadKey decrypts a JWK and returns a LoadedKey.
func (km *KeyManager) decryptAndLoadKey(jwk *JWK) (*LoadedKey, error) {
	// Decrypt private key
	privateKeyPEM, err := km.encryptor.Decrypt(jwk.PrivateKeyEnc)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyDecryption, err)
	}

	// Parse private key
	privateKey, publicKey, err := km.parsePrivateKey([]byte(privateKeyPEM), jwk.KeyType)
	if err != nil {
		return nil, err
	}

	return &LoadedKey{
		ID:          jwk.ID,
		Algorithm:   jwk.Algorithm,
		Status:      jwk.Status,
		PrivateKey:  privateKey,
		PublicKey:   publicKey,
		ActivatedAt: jwk.ActivatedAt,
		ExpiresAt:   jwk.ExpiresAt,
	}, nil
}

// marshalPrivateKey serializes a private key to PEM format.
func (km *KeyManager) marshalPrivateKey(key crypto.PrivateKey) ([]byte, error) {
	var derBytes []byte
	var pemType string

	switch k := key.(type) {
	case *rsa.PrivateKey:
		derBytes = x509.MarshalPKCS1PrivateKey(k)
		pemType = "RSA PRIVATE KEY"
	case *ecdsa.PrivateKey:
		var err error
		derBytes, err = x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ECDSA private key: %w", err)
		}
		pemType = "EC PRIVATE KEY"
	case ed25519.PrivateKey:
		var err error
		derBytes, err = x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Ed25519 private key: %w", err)
		}
		pemType = "PRIVATE KEY"
	default:
		return nil, fmt.Errorf("unsupported key type: %T", key)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  pemType,
		Bytes: derBytes,
	}), nil
}

// parsePrivateKey parses a PEM-encoded private key.
func (km *KeyManager) parsePrivateKey(pemBytes []byte, keyType string) (crypto.PrivateKey, crypto.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode PEM block")
	}

	switch keyType {
	case KeyTypeRSA:
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse RSA private key: %w", err)
		}
		return key, &key.PublicKey, nil

	case KeyTypeEC:
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse ECDSA private key: %w", err)
		}
		return key, &key.PublicKey, nil

	case KeyTypeOKP:
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse Ed25519 private key: %w", err)
		}
		ed25519Key, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("unexpected key type from PKCS8")
		}
		return ed25519Key, ed25519Key.Public(), nil

	default:
		return nil, nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
}

// publicKeyToJWK converts a public key to JWK JSON format.
func (km *KeyManager) publicKeyToJWK(key crypto.PublicKey, keyType string) (string, error) {
	var jwk JWKPublic

	switch k := key.(type) {
	case *rsa.PublicKey:
		jwk = JWKPublic{
			Kty: KeyTypeRSA,
			N:   base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
		}

	case *ecdsa.PublicKey:
		var crv string
		switch k.Curve {
		case elliptic.P256():
			crv = "P-256"
		case elliptic.P384():
			crv = "P-384"
		case elliptic.P521():
			crv = "P-521"
		default:
			return "", fmt.Errorf("unsupported curve")
		}

		byteLen := (k.Curve.Params().BitSize + 7) / 8
		xBytes := k.X.Bytes()
		yBytes := k.Y.Bytes()

		// Pad to correct length
		xPadded := make([]byte, byteLen)
		yPadded := make([]byte, byteLen)
		copy(xPadded[byteLen-len(xBytes):], xBytes)
		copy(yPadded[byteLen-len(yBytes):], yBytes)

		jwk = JWKPublic{
			Kty: KeyTypeEC,
			Crv: crv,
			X:   base64.RawURLEncoding.EncodeToString(xPadded),
			Y:   base64.RawURLEncoding.EncodeToString(yPadded),
		}

	case ed25519.PublicKey:
		jwk = JWKPublic{
			Kty: KeyTypeOKP,
			Crv: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(k),
		}

	default:
		return "", fmt.Errorf("unsupported public key type: %T", key)
	}

	data, err := json.Marshal(jwk)
	if err != nil {
		return "", err
	}

	return string(data), nil
}
