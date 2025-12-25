// Package token provides cryptographic utilities for token generation, hashing, and encryption.
package token

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
)

const (
	// DefaultTokenLength is the default length of generated tokens in bytes
	DefaultTokenLength = 32
)

var (
	ErrEncryptionFailed  = errors.New("encryption failed")
	ErrDecryptionFailed  = errors.New("decryption failed")
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
)

// Generate creates a cryptographically secure random token
func Generate() (string, error) {
	return GenerateWithLength(DefaultTokenLength)
}

// GenerateWithLength creates a random token with specified length
func GenerateWithLength(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// Hasher creates HMAC-SHA256 hashes of tokens
type Hasher struct {
	secret []byte
}

// NewHasher creates a new Hasher with the given secret
func NewHasher(secret string) *Hasher {
	return &Hasher{secret: []byte(secret)}
}

// Hash creates an HMAC-SHA256 hash of the token
func (h *Hasher) Hash(token string) string {
	mac := hmac.New(sha256.New, h.secret)
	mac.Write([]byte(token))
	return hex.EncodeToString(mac.Sum(nil))
}

// Encryptor handles AES-256-GCM encryption for sensitive data like OAuth tokens
type Encryptor struct {
	key []byte
}

// NewEncryptor creates a new Encryptor
// The secret should be at least 32 bytes for AES-256
func NewEncryptor(secret string) *Encryptor {
	// Derive a 32-byte key from the secret using SHA-256
	hash := sha256.Sum256([]byte(secret))
	return &Encryptor{key: hash[:]}
}

// Encrypt encrypts plaintext using AES-256-GCM
func (e *Encryptor) Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", ErrEncryptionFailed
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", ErrEncryptionFailed
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", ErrEncryptionFailed
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts ciphertext using AES-256-GCM
func (e *Encryptor) Decrypt(ciphertext string) (string, error) {
	data, err := base64.URLEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", ErrInvalidCiphertext
	}

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", ErrDecryptionFailed
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", ErrDecryptionFailed
	}

	if len(data) < gcm.NonceSize() {
		return "", ErrInvalidCiphertext
	}

	nonce := data[:gcm.NonceSize()]
	ciphertextBytes := data[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", ErrDecryptionFailed
	}

	return string(plaintext), nil
}
