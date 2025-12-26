package models

import (
	"strings"
	"testing"
)

func TestNewArgon2PasswordHasher(t *testing.T) {
	hasher := NewArgon2PasswordHasher()

	if hasher == nil {
		t.Fatal("NewArgon2PasswordHasher returned nil")
	}
	if hasher.params == nil {
		t.Fatal("Params should not be nil")
	}
}

func TestNewArgon2PasswordHasherWithParams(t *testing.T) {
	hasher := NewArgon2PasswordHasherWithParams(
		32*1024, // 32 MB memory
		2,       // 2 iterations
		2,       // 2 parallelism
		16,      // 16 byte salt
		32,      // 32 byte key
	)

	if hasher == nil {
		t.Fatal("NewArgon2PasswordHasherWithParams returned nil")
	}
	if hasher.params.Memory != 32*1024 {
		t.Errorf("Memory = %d, want %d", hasher.params.Memory, 32*1024)
	}
	if hasher.params.Iterations != 2 {
		t.Errorf("Iterations = %d, want 2", hasher.params.Iterations)
	}
	if hasher.params.Parallelism != 2 {
		t.Errorf("Parallelism = %d, want 2", hasher.params.Parallelism)
	}
	if hasher.params.SaltLength != 16 {
		t.Errorf("SaltLength = %d, want 16", hasher.params.SaltLength)
	}
	if hasher.params.KeyLength != 32 {
		t.Errorf("KeyLength = %d, want 32", hasher.params.KeyLength)
	}
}

func TestArgon2PasswordHasher_Hash(t *testing.T) {
	hasher := NewArgon2PasswordHasher()

	password := "testPassword123!"
	hash, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	// Hash should be non-empty
	if hash == "" {
		t.Error("Hash should not be empty")
	}

	// Hash should start with argon2id identifier
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("Hash should start with $argon2id$, got: %s", hash)
	}

	// Hash should be different from password
	if hash == password {
		t.Error("Hash should be different from password")
	}
}

func TestArgon2PasswordHasher_HashUniqueSalt(t *testing.T) {
	hasher := NewArgon2PasswordHasher()
	password := "samePassword123!"

	hash1, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("First hash failed: %v", err)
	}

	hash2, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("Second hash failed: %v", err)
	}

	// Same password should produce different hashes due to random salt
	if hash1 == hash2 {
		t.Error("Same password should produce different hashes (different salts)")
	}
}

func TestArgon2PasswordHasher_Verify(t *testing.T) {
	hasher := NewArgon2PasswordHasher()
	password := "correctPassword123!"

	hash, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	// Correct password should verify
	if !hasher.Verify(password, hash) {
		t.Error("Correct password should verify")
	}

	// Incorrect password should not verify
	if hasher.Verify("wrongPassword", hash) {
		t.Error("Incorrect password should not verify")
	}

	// Empty password should not verify
	if hasher.Verify("", hash) {
		t.Error("Empty password should not verify")
	}

	// Similar password should not verify
	if hasher.Verify("correctPassword123", hash) {
		t.Error("Similar password (missing !) should not verify")
	}
}

func TestArgon2PasswordHasher_VerifyInvalidHash(t *testing.T) {
	hasher := NewArgon2PasswordHasher()

	// Invalid hash should return false
	if hasher.Verify("password", "not-a-valid-hash") {
		t.Error("Invalid hash should return false")
	}

	// Empty hash should return false
	if hasher.Verify("password", "") {
		t.Error("Empty hash should return false")
	}

	// Malformed argon2 hash should return false
	if hasher.Verify("password", "$argon2id$v=19$m=invalid") {
		t.Error("Malformed hash should return false")
	}
}

func TestArgon2PasswordHasher_VariousPasswords(t *testing.T) {
	hasher := NewArgon2PasswordHasher()

	passwords := []string{
		"simple",
		"Complex123!@#",
		"verylongpasswordthatexceedsnormallengthexpectations",
		"unicode-пароль-密码",
		"spaces in password",
		"!@#$%^&*()",
		"12345678",
		"a", // Single character
	}

	for _, password := range passwords {
		t.Run(password, func(t *testing.T) {
			hash, err := hasher.Hash(password)
			if err != nil {
				t.Fatalf("Hash failed for %q: %v", password, err)
			}

			if !hasher.Verify(password, hash) {
				t.Errorf("Verify failed for %q", password)
			}
		})
	}
}

func TestArgon2PasswordHasher_EmptyPassword(t *testing.T) {
	hasher := NewArgon2PasswordHasher()

	// Empty password should still hash (though not recommended)
	hash, err := hasher.Hash("")
	if err != nil {
		t.Fatalf("Hash failed for empty password: %v", err)
	}

	// Should verify correctly
	if !hasher.Verify("", hash) {
		t.Error("Empty password should verify against its own hash")
	}

	// Non-empty password should not verify
	if hasher.Verify("notempty", hash) {
		t.Error("Non-empty password should not verify against empty password hash")
	}
}

func TestPasswordHasher_Interface(t *testing.T) {
	// Ensure Argon2PasswordHasher implements PasswordHasher
	var _ PasswordHasher = (*Argon2PasswordHasher)(nil)
}

func BenchmarkArgon2PasswordHasher_Hash(b *testing.B) {
	hasher := NewArgon2PasswordHasher()
	password := "benchmarkPassword123!"

	for b.Loop() {
		_, _ = hasher.Hash(password)
	}
}

func BenchmarkArgon2PasswordHasher_Verify(b *testing.B) {
	hasher := NewArgon2PasswordHasher()
	password := "benchmarkPassword123!"
	hash, _ := hasher.Hash(password)

	for b.Loop() {
		_ = hasher.Verify(password, hash)
	}
}
