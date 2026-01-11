package jwt

import (
	"context"
	"encoding/json"
	"net/http"
)

// JWKS represents a JSON Web Key Set.
// This is the format returned by the /.well-known/jwks.json endpoint.
type JWKS struct {
	Keys []JWKPublic `json:"keys"`
}

// JWKPublic represents a public JSON Web Key.
// Only the public components are exposed - private keys are never included.
type JWKPublic struct {
	// Common fields
	Kty string `json:"kty"`           // Key Type: RSA, EC, OKP
	Use string `json:"use,omitempty"` // Key Use: sig (signature)
	Alg string `json:"alg,omitempty"` // Algorithm: RS256, ES256, EdDSA
	Kid string `json:"kid,omitempty"` // Key ID

	// RSA fields
	N string `json:"n,omitempty"` // Modulus (base64url)
	E string `json:"e,omitempty"` // Exponent (base64url)

	// EC and OKP fields
	Crv string `json:"crv,omitempty"` // Curve: P-256, P-384, P-521, Ed25519
	X   string `json:"x,omitempty"`   // X coordinate (base64url)
	Y   string `json:"y,omitempty"`   // Y coordinate (base64url, EC only)
}

// JWKSProvider is an interface for retrieving JWKS.
// Implemented by both KeyManager and KeyManagerAdapter.
type JWKSProvider interface {
	GetJWKS(ctx context.Context) (*JWKS, error)
}

// JWKSHandler returns an HTTP handler that serves the JWKS endpoint.
// This handler should be mounted at /.well-known/jwks.json
func JWKSHandler(km JWKSProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		jwks, err := km.GetJWKS(r.Context())
		if err != nil {
			http.Error(w, "Failed to retrieve keys", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour
		if err := json.NewEncoder(w).Encode(jwks); err != nil {
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		}
	}
}
