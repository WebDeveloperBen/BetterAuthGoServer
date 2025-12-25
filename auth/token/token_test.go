package token

import (
	"testing"
)

func TestGenerate(t *testing.T) {
	token1, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if len(token1) == 0 {
		t.Error("Generate() returned empty token")
	}

	// Tokens should be unique
	token2, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if token1 == token2 {
		t.Error("Generate() returned duplicate tokens")
	}
}

func TestHasher(t *testing.T) {
	secret := "test-secret-key-32-chars-long!!"
	hasher := NewHasher(secret)

	token := "test-token-value"

	// Hash should be deterministic
	hash1 := hasher.Hash(token)
	hash2 := hasher.Hash(token)

	if hash1 != hash2 {
		t.Error("Hash() is not deterministic")
	}

	// Different tokens should produce different hashes
	hash3 := hasher.Hash("different-token")
	if hash1 == hash3 {
		t.Error("Hash() produced same hash for different tokens")
	}

	// Hash should not be empty
	if len(hash1) == 0 {
		t.Error("Hash() returned empty hash")
	}
}

func TestHasherDifferentSecrets(t *testing.T) {
	hasher1 := NewHasher("secret-one-32-chars-long-here!!")
	hasher2 := NewHasher("secret-two-32-chars-long-here!!")

	token := "same-token"

	hash1 := hasher1.Hash(token)
	hash2 := hasher2.Hash(token)

	if hash1 == hash2 {
		t.Error("Different secrets produced same hash")
	}
}

func TestEncryptor(t *testing.T) {
	secret := "test-secret-key-32-chars-long!!"
	encryptor := NewEncryptor(secret)

	plaintext := "sensitive-data-to-encrypt"

	// Encrypt
	ciphertext, err := encryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	if ciphertext == plaintext {
		t.Error("Encrypt() did not encrypt the data")
	}

	// Decrypt
	decrypted, err := encryptor.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Decrypt() = %v, want %v", decrypted, plaintext)
	}
}

func TestEncryptorDifferentCiphertexts(t *testing.T) {
	secret := "test-secret-key-32-chars-long!!"
	encryptor := NewEncryptor(secret)

	plaintext := "same-plaintext"

	// Each encryption should produce different ciphertext (due to random nonce)
	cipher1, _ := encryptor.Encrypt(plaintext)
	cipher2, _ := encryptor.Encrypt(plaintext)

	if cipher1 == cipher2 {
		t.Error("Encrypt() produced same ciphertext for same plaintext (should use random nonce)")
	}

	// Both should decrypt to same plaintext
	dec1, _ := encryptor.Decrypt(cipher1)
	dec2, _ := encryptor.Decrypt(cipher2)

	if dec1 != dec2 {
		t.Error("Different ciphertexts decrypted to different plaintexts")
	}
}

func TestEncryptorInvalidCiphertext(t *testing.T) {
	secret := "test-secret-key-32-chars-long!!"
	encryptor := NewEncryptor(secret)

	// Try to decrypt invalid data
	_, err := encryptor.Decrypt("not-valid-ciphertext")
	if err == nil {
		t.Error("Decrypt() should fail for invalid ciphertext")
	}
}

func TestEncryptorWrongSecret(t *testing.T) {
	encryptor1 := NewEncryptor("secret-one-32-chars-long-here!!")
	encryptor2 := NewEncryptor("secret-two-32-chars-long-here!!")

	plaintext := "sensitive-data"
	ciphertext, _ := encryptor1.Encrypt(plaintext)

	// Decrypting with wrong secret should fail
	_, err := encryptor2.Decrypt(ciphertext)
	if err == nil {
		t.Error("Decrypt() should fail with wrong secret")
	}
}

func TestEncryptorEmptyString(t *testing.T) {
	secret := "test-secret-key-32-chars-long!!"
	encryptor := NewEncryptor(secret)

	// Empty string should work
	ciphertext, err := encryptor.Encrypt("")
	if err != nil {
		t.Fatalf("Encrypt() error for empty string = %v", err)
	}

	decrypted, err := encryptor.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt() error for empty string = %v", err)
	}

	if decrypted != "" {
		t.Errorf("Decrypt() = %v, want empty string", decrypted)
	}
}
