package password

import (
	"github.com/alexedwards/argon2id"
)

// PasswordHasher defines the interface for password hashing.
type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(password, hash string) bool
}

// Argon2PasswordHasher implements PasswordHasher using Argon2id.
type Argon2PasswordHasher struct {
	params *argon2id.Params
}

// NewArgon2PasswordHasher creates a new Argon2PasswordHasher with default params.
func NewArgon2PasswordHasher() *Argon2PasswordHasher {
	return &Argon2PasswordHasher{
		params: argon2id.DefaultParams,
	}
}

// NewArgon2PasswordHasherWithParams creates a new Argon2PasswordHasher with custom params.
func NewArgon2PasswordHasherWithParams(memory, iterations uint32, parallelism uint8, saltLength, keyLength uint32) *Argon2PasswordHasher {
	return &Argon2PasswordHasher{
		params: &argon2id.Params{
			Memory:      memory,
			Iterations:  iterations,
			Parallelism: parallelism,
			SaltLength:  saltLength,
			KeyLength:   keyLength,
		},
	}
}

// Hash creates an Argon2id hash of the password.
func (h *Argon2PasswordHasher) Hash(password string) (string, error) {
	return argon2id.CreateHash(password, h.params)
}

// Verify checks if a password matches the hash.
func (h *Argon2PasswordHasher) Verify(password, hash string) bool {
	match, err := argon2id.ComparePasswordAndHash(password, hash)
	if err != nil {
		return false
	}
	return match
}
