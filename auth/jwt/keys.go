package jwt

import (
	"time"

	"github.com/uptrace/bun"
)

// JWK represents a JSON Web Key stored in the database.
// Private keys are encrypted at rest using AES-256-GCM.
type JWK struct {
	bun.BaseModel `bun:"table:jwt_keys,alias:jk"`

	// ID is the key identifier (kid) used in JWT headers
	ID string `bun:"id,pk"`

	// Algorithm is the signing algorithm (RS256, ES256, EdDSA)
	Algorithm string `bun:"algorithm,notnull"`

	// Use is the key usage ("sig" for signature)
	Use string `bun:"use,notnull"`

	// KeyType is the key type (RSA, EC, OKP)
	KeyType string `bun:"kty,notnull"`

	// Status is the key status (active, rotating, retired)
	Status string `bun:"status,notnull"`

	// PrivateKeyEnc is the encrypted private key (AES-256-GCM)
	PrivateKeyEnc string `bun:"private_key_enc,notnull"`

	// PublicKeyJWK is the public key in JWK JSON format
	PublicKeyJWK string `bun:"public_key_jwk,notnull"`

	// ActivatedAt is when the key became active
	ActivatedAt time.Time `bun:"activated_at,notnull"`

	// RotatedAt is when the key was rotated (moved to rotating status)
	RotatedAt *time.Time `bun:"rotated_at"`

	// ExpiresAt is when the key expires and can no longer be used for verification
	ExpiresAt *time.Time `bun:"expires_at"`

	// CreatedAt is when the key was created
	CreatedAt time.Time `bun:"created_at,notnull,default:current_timestamp"`

	// UpdatedAt is when the key was last updated
	UpdatedAt time.Time `bun:"updated_at,notnull,default:current_timestamp"`
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
