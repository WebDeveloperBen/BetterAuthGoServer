# JWT Plugin

The JWT plugin provides JSON Web Token authentication with support for both symmetric (HMAC) and asymmetric (RSA, ECDSA, EdDSA) algorithms. It includes database-backed key management with encryption at rest, automatic key rotation, and a JWKS endpoint for public key distribution.

## Features

- **Multiple Algorithms**: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512, EdDSA
- **Database-Backed Keys**: Asymmetric keys stored encrypted (AES-256-GCM) in the database
- **Key Rotation**: Automatic grace period for old keys during rotation
- **JWKS Endpoint**: Standard `/.well-known/jwks.json` for public key distribution
- **Token Blocklist**: Revoke tokens before expiry (database or in-memory)
- **Impersonation Support**: RFC 8693 actor claims for admin impersonation scenarios

## Quick Start

### Basic HMAC Setup (Simplest)

```go
import "github.com/webdeveloperben/BetterAuthGoServer/auth/jwt"

authService.Use(jwt.NewPlugin(
    jwt.WithAlgorithm(jwt.AlgorithmHS256),
    // Secret is inherited from auth config by default
))
```

### Asymmetric with Database Keys (Recommended for Production)

```go
authService.Use(jwt.NewPlugin(
    jwt.WithAlgorithm(jwt.AlgorithmES256),
    jwt.WithKeySource(jwt.KeySourceDatabase),
    jwt.WithKeyRotationGracePeriod(24 * time.Hour),
))
```

### Asymmetric with Config-Provided Keys

```go
privateKey, _ := os.ReadFile("private.pem")
publicKey, _ := os.ReadFile("public.pem")

authService.Use(jwt.NewPlugin(
    jwt.WithAlgorithm(jwt.AlgorithmRS256),
    jwt.WithPrivateKey(privateKey),
    jwt.WithPublicKey(publicKey),
))
```

## Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `WithAlgorithm(alg)` | Signing algorithm | `HS256` |
| `WithAccessTTL(duration)` | Access token lifetime | `15m` |
| `WithRefreshTTL(duration)` | Refresh token lifetime | `7d` |
| `WithIssuer(string)` | Token issuer claim | Base URL |
| `WithAudience(string)` | Token audience claim | - |
| `WithKeySource(source)` | Key source: `KeySourceConfig` or `KeySourceDatabase` | `KeySourceConfig` |
| `WithPrivateKey([]byte)` | PEM-encoded private key (for config source) | - |
| `WithPublicKey([]byte)` | PEM-encoded public key (for config source) | - |
| `WithKeyRotationGracePeriod(duration)` | How long rotated keys remain valid | `24h` |
| `WithKeySize(int)` | RSA key size (only for RSA algorithms) | `2048` |
| `WithTokenBlocklist(blocklist)` | Custom token blocklist implementation | Auto (DB or memory) |

## Algorithms

### Symmetric (HMAC)
- **HS256, HS384, HS512**: Use the auth secret for signing/verification
- Simple setup, no key management needed
- Not suitable for scenarios where tokens are verified by third parties

### Asymmetric (RSA)
- **RS256, RS384, RS512**: RSA with SHA-256/384/512
- Default key size: 2048 bits (configurable)
- Good compatibility with existing systems

### Asymmetric (ECDSA)
- **ES256**: ECDSA with P-256 curve
- **ES384**: ECDSA with P-384 curve
- **ES512**: ECDSA with P-521 curve
- Smaller keys, faster operations than RSA

### Asymmetric (EdDSA)
- **EdDSA**: Ed25519 curve
- Modern, fast, small signatures
- Recommended for new implementations

## Endpoints

### Token Operations

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/token` | Get tokens (password or refresh grant) |
| `POST` | `/token/refresh` | Refresh tokens |
| `POST` | `/token/revoke` | Revoke a token |
| `POST` | `/token/introspect` | Inspect token claims |

### Key Management (Database-Backed Keys Only)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/.well-known/jwks.json` | Public keys in JWKS format |
| `POST` | `/keys/rotate` | Force key rotation |

## Token Request Examples

### Password Grant
```bash
curl -X POST /auth/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type": "password", "email": "user@example.com", "password": "secret"}'
```

### Refresh Grant
```bash
curl -X POST /auth/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type": "refresh_token", "refresh_token": "..."}'
```

### Token Response
```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJFUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

## Key Management

### Database-Backed Keys

When using `KeySourceDatabase`, the plugin:

1. **Stores keys encrypted**: Private keys are encrypted with AES-256-GCM using the auth secret
2. **Manages key lifecycle**: Keys have statuses: `active`, `rotating`, `retired`
3. **Handles rotation**: Old keys remain valid for verification during the grace period
4. **Provides JWKS**: Public keys are exposed at `/.well-known/jwks.json`

### Key Rotation Flow

1. New key is generated and marked `active`
2. Previous active key moves to `rotating` status with an expiry time
3. Both keys are included in JWKS for verification
4. After grace period, rotating keys are marked `retired` and removed from JWKS
5. Tokens signed with rotated keys remain valid until their expiry

### JWKS Response Example
```json
{
  "keys": [
    {
      "kty": "EC",
      "use": "sig",
      "alg": "ES256",
      "kid": "550e8400-e29b-41d4-a716-446655440000",
      "crv": "P-256",
      "x": "...",
      "y": "..."
    }
  ]
}
```

## Token Claims

### Access Token Claims
| Claim | Description |
|-------|-------------|
| `sub` | User ID |
| `uid` | User ID (convenience) |
| `sid` | Session ID |
| `email` | User email |
| `name` | User name |
| `email_verified` | Email verification status |
| `type` | Token type (`access`) |
| `iss` | Issuer |
| `aud` | Audience |
| `exp` | Expiration time |
| `iat` | Issued at |
| `jti` | Unique token ID |
| `act` | Actor claim (for impersonation) |

### Refresh Token Claims
Refresh tokens include: `sub`, `uid`, `sid`, `type`, `iss`, `aud`, `exp`, `iat`, `jti`, `act`

## Middleware

The plugin provides JWT authentication middleware that:

1. Extracts the Bearer token from the `Authorization` header
2. Validates the token signature and claims
3. Checks the token blocklist
4. Sets user and claims in the request context

```go
// Access claims in handlers
claims := jwt.GetJWTClaims(r.Context())
user := jwt.GetJWTUser(r.Context())
```

## Security Considerations

1. **Secret Length**: Use a secret of at least 32 characters for HMAC algorithms
2. **Key Rotation**: Rotate asymmetric keys periodically (e.g., every 90 days)
3. **Grace Period**: Set grace period long enough for clients to refresh tokens
4. **Token Lifetime**: Keep access tokens short-lived (15 minutes recommended)
5. **Blocklist**: Enable token blocklist for logout/revocation scenarios
6. **HTTPS**: Always use HTTPS in production

## Database Schema

When using database-backed keys, the plugin creates:

### `jwt_keys` Table
| Column | Type | Description |
|--------|------|-------------|
| `id` | string (PK) | Key ID (UUID, used as `kid`) |
| `algorithm` | string | Signing algorithm |
| `use` | string | Key use (`sig`) |
| `kty` | string | Key type (RSA, EC, OKP) |
| `status` | string | Key status |
| `private_key_enc` | string | Encrypted private key |
| `public_key_jwk` | string | Public key in JWK format |
| `activated_at` | timestamp | When key became active |
| `rotated_at` | timestamp | When key was rotated |
| `expires_at` | timestamp | When key expires |
| `created_at` | timestamp | Creation time |
| `updated_at` | timestamp | Last update time |

### `revoked_tokens` Table
| Column | Type | Description |
|--------|------|-------------|
| `jti` | string (PK) | Token ID |
| `expires_at` | timestamp | When the revocation expires |
| `created_at` | timestamp | When token was revoked |
