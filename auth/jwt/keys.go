package jwt

import (
	"time"
)

// JWK represents a JSON Web Key.
// Private keys are encrypted at rest using AES-256-GCM.
type JWK struct {
	// ID is the key identifier (kid) used in JWT headers
	ID string

	// Algorithm is the signing algorithm (RS256, ES256, EdDSA)
	Algorithm string

	// Use is the key usage ("sig" for signature)
	Use string

	// KeyType is the key type (RSA, EC, OKP)
	KeyType string

	// Status is the key status (active, rotating, retired)
	Status string

	// PrivateKeyEnc is the encrypted private key (AES-256-GCM)
	PrivateKeyEnc string

	// PublicKeyJWK is the public key in JWK JSON format
	PublicKeyJWK string

	// ActivatedAt is when the key became active
	ActivatedAt time.Time

	// RotatedAt is when the key was rotated (moved to rotating status)
	RotatedAt *time.Time

	// ExpiresAt is when the key expires and can no longer be used for verification
	ExpiresAt *time.Time

	// CreatedAt is when the key was created
	CreatedAt time.Time

	// UpdatedAt is when the key was last updated
	UpdatedAt time.Time
}

// Key status constants
const (
	// KeyStatusActive indicates the key is the current signing key
	KeyStatusActive = "active"

	// KeyStatusRotating indicates the key is in grace period (can verify, cannot sign)
	KeyStatusRotating = "rotating"

	// KeyStatusRetired indicates the key is no longer valid
	KeyStatusRetired = "retired"
)

// Key use constants
const (
	// KeyUseSignature indicates the key is used for signatures
	KeyUseSignature = "sig"
)

// Key type constants (JWK kty values)
const (
	// KeyTypeRSA is for RSA keys
	KeyTypeRSA = "RSA"

	// KeyTypeEC is for Elliptic Curve keys
	KeyTypeEC = "EC"

	// KeyTypeOKP is for Octet Key Pair (Ed25519)
	KeyTypeOKP = "OKP"
)

// KeySource indicates where keys are sourced from
type KeySource string

const (
	// KeySourceConfig uses keys from the Config struct (PrivateKey/PublicKey PEM fields)
	KeySourceConfig KeySource = "config"

	// KeySourceDatabase uses database-backed keys with encryption and rotation support
	KeySourceDatabase KeySource = "database"
)
