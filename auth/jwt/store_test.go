package jwt

import (
	"context"
	"testing"
	"time"

	"github.com/uptrace/bun"
)

func TestMemoryTokenBlocklist(t *testing.T) {
	blocklist := NewMemoryTokenBlocklist()
	ctx := context.Background()

	// Test revoking a token
	jti := "test-jti-123"
	expiresAt := time.Now().Add(time.Hour)

	err := blocklist.Revoke(ctx, jti, expiresAt)
	if err != nil {
		t.Fatalf("Revoke() failed: %v", err)
	}

	// Test checking if token is revoked
	revoked, err := blocklist.IsRevoked(ctx, jti)
	if err != nil {
		t.Fatalf("IsRevoked() failed: %v", err)
	}
	if !revoked {
		t.Error("Expected token to be revoked")
	}

	// Test checking non-revoked token
	revoked, err = blocklist.IsRevoked(ctx, "non-existent-jti")
	if err != nil {
		t.Fatalf("IsRevoked() failed: %v", err)
	}
	if revoked {
		t.Error("Expected non-existent token to not be revoked")
	}

	// Test expired token cleanup
	expiredJTI := "expired-jti"
	expiredAt := time.Now().Add(-time.Hour) // Already expired

	err = blocklist.Revoke(ctx, expiredJTI, expiredAt)
	if err != nil {
		t.Fatalf("Revoke() failed: %v", err)
	}

	// Should return false for expired token (and clean it up)
	revoked, err = blocklist.IsRevoked(ctx, expiredJTI)
	if err != nil {
		t.Fatalf("IsRevoked() failed: %v", err)
	}
	if revoked {
		t.Error("Expected expired token to not be considered revoked")
	}

	// Check that expired token was cleaned up by checking again
	revoked, err = blocklist.IsRevoked(ctx, expiredJTI)
	if err != nil {
		t.Fatalf("IsRevoked() failed: %v", err)
	}
	if revoked {
		t.Error("Expected expired token to be cleaned up")
	}
}

func TestDBTokenBlocklist_Constructor(t *testing.T) {
	// Test that constructor works
	var db *bun.DB // nil DB for testing
	blocklist := NewDBTokenBlocklist(db)

	if blocklist == nil {
		t.Fatal("NewDBTokenBlocklist returned nil")
	}

	if blocklist.db != db {
		t.Error("DB not set correctly in blocklist")
	}
}

func TestRevokedToken_TableName(t *testing.T) {
	token := &RevokedToken{}
	expected := "jwt_revoked_tokens"

	if token.TableName() != expected {
		t.Errorf("TableName() = %s, want %s", token.TableName(), expected)
	}
}
