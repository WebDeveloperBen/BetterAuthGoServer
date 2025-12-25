package oauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/token"
	"golang.org/x/oauth2"
)

// Mock implementations

type mockStateStore struct {
	states         map[string]*State
	createErr      error
	getErr         error
	deleteErr      error
}

func newMockStateStore() *mockStateStore {
	return &mockStateStore{
		states: make(map[string]*State),
	}
}

func (m *mockStateStore) CreateOAuthState(ctx context.Context, state *State) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.states[state.State] = state
	return nil
}

func (m *mockStateStore) GetOAuthState(ctx context.Context, stateValue string) (*State, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	return m.states[stateValue], nil
}

func (m *mockStateStore) DeleteOAuthState(ctx context.Context, stateValue string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.states, stateValue)
	return nil
}

func (m *mockStateStore) DeleteExpiredOAuthStates(ctx context.Context) error {
	now := time.Now()
	for k, v := range m.states {
		if v.ExpiresAt.Before(now) {
			delete(m.states, k)
		}
	}
	return nil
}

type mockProvider struct {
	name         string
	requiresPKCE bool
	config       *oauth2.Config
	userInfo     *UserInfo
	exchangeErr  error
	userInfoErr  error
}

func (m *mockProvider) Name() string {
	return m.name
}

func (m *mockProvider) Config() *oauth2.Config {
	return m.config
}

func (m *mockProvider) GetUserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	if m.userInfoErr != nil {
		return nil, m.userInfoErr
	}
	return m.userInfo, nil
}

func (m *mockProvider) RequiresPKCE() bool {
	return m.requiresPKCE
}

// Tests

func TestNewService(t *testing.T) {
	store := newMockStateStore()
	hasher := token.NewHasher("test-secret-32-bytes-minimum!!!")
	encryptor := token.NewEncryptor("test-secret-32-bytes-minimum!!!")

	service := NewService(store, hasher, encryptor)

	if service == nil {
		t.Fatal("NewService returned nil")
	}
	if service.stateStore != store {
		t.Error("state store not set correctly")
	}
}

func TestService_RegisterProvider(t *testing.T) {
	store := newMockStateStore()
	hasher := token.NewHasher("test-secret-32-bytes-minimum!!!")
	encryptor := token.NewEncryptor("test-secret-32-bytes-minimum!!!")
	service := NewService(store, hasher, encryptor)

	provider := &mockProvider{
		name: "test",
		config: &oauth2.Config{
			ClientID: "client-id",
		},
	}

	service.RegisterProvider(provider)

	// Verify provider is registered
	p, ok := service.GetProvider("test")
	if !ok {
		t.Fatal("provider should be registered")
	}
	if p.Name() != "test" {
		t.Errorf("provider name = %s, want test", p.Name())
	}
}

func TestService_GetProvider_NotFound(t *testing.T) {
	store := newMockStateStore()
	hasher := token.NewHasher("test-secret-32-bytes-minimum!!!")
	encryptor := token.NewEncryptor("test-secret-32-bytes-minimum!!!")
	service := NewService(store, hasher, encryptor)

	_, ok := service.GetProvider("nonexistent")
	if ok {
		t.Error("should return false for non-existent provider")
	}
}

func TestService_ListProviders(t *testing.T) {
	store := newMockStateStore()
	hasher := token.NewHasher("test-secret-32-bytes-minimum!!!")
	encryptor := token.NewEncryptor("test-secret-32-bytes-minimum!!!")
	service := NewService(store, hasher, encryptor)

	// Register multiple providers
	service.RegisterProvider(&mockProvider{name: "google"})
	service.RegisterProvider(&mockProvider{name: "github"})
	service.RegisterProvider(&mockProvider{name: "facebook"})

	providers := service.ListProviders()
	if len(providers) != 3 {
		t.Errorf("got %d providers, want 3", len(providers))
	}

	// Check all are present (order not guaranteed)
	found := make(map[string]bool)
	for _, p := range providers {
		found[p] = true
	}
	if !found["google"] || !found["github"] || !found["facebook"] {
		t.Error("not all providers returned")
	}
}

func TestService_ListProviders_Empty(t *testing.T) {
	store := newMockStateStore()
	hasher := token.NewHasher("test-secret-32-bytes-minimum!!!")
	encryptor := token.NewEncryptor("test-secret-32-bytes-minimum!!!")
	service := NewService(store, hasher, encryptor)

	providers := service.ListProviders()
	if len(providers) != 0 {
		t.Errorf("got %d providers, want 0", len(providers))
	}
}

func TestState_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{
			name:      "not expired",
			expiresAt: time.Now().Add(10 * time.Minute),
			want:      false,
		},
		{
			name:      "expired",
			expiresAt: time.Now().Add(-10 * time.Minute),
			want:      true,
		},
		{
			name:      "just expired",
			expiresAt: time.Now().Add(-1 * time.Millisecond),
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := &State{
				ExpiresAt: tt.expiresAt,
			}
			if got := state.IsExpired(); got != tt.want {
				t.Errorf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestService_Begin_Success(t *testing.T) {
	store := newMockStateStore()
	hasher := token.NewHasher("test-secret-32-bytes-minimum!!!")
	encryptor := token.NewEncryptor("test-secret-32-bytes-minimum!!!")
	service := NewService(store, hasher, encryptor)

	provider := &mockProvider{
		name:         "test",
		requiresPKCE: false,
		config: &oauth2.Config{
			ClientID:    "client-id",
			RedirectURL: "http://localhost/callback",
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://auth.example.com/authorize",
				TokenURL: "https://auth.example.com/token",
			},
		},
	}
	service.RegisterProvider(provider)

	result, err := service.Begin(context.Background(), "test", "http://localhost/redirect")
	if err != nil {
		t.Fatalf("Begin failed: %v", err)
	}

	if result.URL == "" {
		t.Error("URL should not be empty")
	}
	if result.State == "" {
		t.Error("State should not be empty")
	}
	if result.Verifier != "" {
		t.Error("Verifier should be empty for non-PKCE provider")
	}

	// Verify state is stored
	if len(store.states) != 1 {
		t.Error("state should be stored")
	}
}

func TestService_Begin_WithPKCE(t *testing.T) {
	store := newMockStateStore()
	hasher := token.NewHasher("test-secret-32-bytes-minimum!!!")
	encryptor := token.NewEncryptor("test-secret-32-bytes-minimum!!!")
	service := NewService(store, hasher, encryptor)

	provider := &mockProvider{
		name:         "test-pkce",
		requiresPKCE: true,
		config: &oauth2.Config{
			ClientID:    "client-id",
			RedirectURL: "http://localhost/callback",
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://auth.example.com/authorize",
				TokenURL: "https://auth.example.com/token",
			},
		},
	}
	service.RegisterProvider(provider)

	result, err := service.Begin(context.Background(), "test-pkce", "")
	if err != nil {
		t.Fatalf("Begin failed: %v", err)
	}

	if result.Verifier == "" {
		t.Error("Verifier should be set for PKCE provider")
	}

	// Verify state has verifier
	for _, state := range store.states {
		if state.Verifier == nil {
			t.Error("stored state should have verifier")
		}
	}
}

func TestService_Begin_ProviderNotFound(t *testing.T) {
	store := newMockStateStore()
	hasher := token.NewHasher("test-secret-32-bytes-minimum!!!")
	encryptor := token.NewEncryptor("test-secret-32-bytes-minimum!!!")
	service := NewService(store, hasher, encryptor)

	_, err := service.Begin(context.Background(), "nonexistent", "")
	if !errors.Is(err, ErrProviderNotFound) {
		t.Errorf("error = %v, want ErrProviderNotFound", err)
	}
}

func TestService_Begin_StoreError(t *testing.T) {
	store := newMockStateStore()
	store.createErr = errors.New("store error")
	hasher := token.NewHasher("test-secret-32-bytes-minimum!!!")
	encryptor := token.NewEncryptor("test-secret-32-bytes-minimum!!!")
	service := NewService(store, hasher, encryptor)

	provider := &mockProvider{
		name: "test",
		config: &oauth2.Config{
			ClientID: "client-id",
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://auth.example.com/authorize",
				TokenURL: "https://auth.example.com/token",
			},
		},
	}
	service.RegisterProvider(provider)

	_, err := service.Begin(context.Background(), "test", "")
	if err == nil {
		t.Error("expected error from store")
	}
}

func TestService_EncryptDecryptToken(t *testing.T) {
	store := newMockStateStore()
	hasher := token.NewHasher("test-secret-32-bytes-minimum!!!")
	encryptor := token.NewEncryptor("test-secret-32-bytes-minimum!!!")
	service := NewService(store, hasher, encryptor)

	original := "my-secret-token-value"

	encrypted, err := service.EncryptToken(original)
	if err != nil {
		t.Fatalf("EncryptToken failed: %v", err)
	}

	if encrypted == original {
		t.Error("encrypted token should be different from original")
	}

	decrypted, err := service.DecryptToken(encrypted)
	if err != nil {
		t.Fatalf("DecryptToken failed: %v", err)
	}

	if decrypted != original {
		t.Errorf("decrypted = %s, want %s", decrypted, original)
	}
}

func TestGenerateRandomString(t *testing.T) {
	lengths := []int{16, 32, 64, 128}

	for _, length := range lengths {
		str, err := generateRandomString(length)
		if err != nil {
			t.Fatalf("generateRandomString(%d) failed: %v", length, err)
		}

		if len(str) != length {
			t.Errorf("length = %d, want %d", len(str), length)
		}
	}
}

func TestGenerateRandomString_Unique(t *testing.T) {
	// Generate multiple strings and ensure they're unique
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		str, err := generateRandomString(32)
		if err != nil {
			t.Fatalf("generateRandomString failed: %v", err)
		}

		if seen[str] {
			t.Error("generated duplicate string")
		}
		seen[str] = true
	}
}

func TestGenerateCodeChallenge(t *testing.T) {
	verifier := "test-verifier-value-for-pkce"
	challenge := generateCodeChallenge(verifier)

	if challenge == "" {
		t.Error("challenge should not be empty")
	}
	if challenge == verifier {
		t.Error("challenge should be different from verifier")
	}

	// Challenge should be base64url encoded
	if len(challenge) != 43 { // SHA256 (32 bytes) base64url encoded without padding
		t.Errorf("challenge length = %d, expected 43", len(challenge))
	}
}

func TestGenerateCodeChallenge_Deterministic(t *testing.T) {
	verifier := "same-verifier-produces-same-challenge"

	challenge1 := generateCodeChallenge(verifier)
	challenge2 := generateCodeChallenge(verifier)

	if challenge1 != challenge2 {
		t.Error("same verifier should produce same challenge")
	}
}

func TestService_Complete_ProviderNotFound(t *testing.T) {
	store := newMockStateStore()
	hasher := token.NewHasher("test-secret-32-bytes-minimum!!!")
	encryptor := token.NewEncryptor("test-secret-32-bytes-minimum!!!")
	service := NewService(store, hasher, encryptor)

	_, _, err := service.Complete(context.Background(), "nonexistent", "code", "state")
	if !errors.Is(err, ErrProviderNotFound) {
		t.Errorf("error = %v, want ErrProviderNotFound", err)
	}
}

func TestService_Complete_StateNotFound(t *testing.T) {
	store := newMockStateStore()
	hasher := token.NewHasher("test-secret-32-bytes-minimum!!!")
	encryptor := token.NewEncryptor("test-secret-32-bytes-minimum!!!")
	service := NewService(store, hasher, encryptor)

	provider := &mockProvider{name: "test"}
	service.RegisterProvider(provider)

	_, _, err := service.Complete(context.Background(), "test", "code", "nonexistent-state")
	if !errors.Is(err, ErrStateNotFound) {
		t.Errorf("error = %v, want ErrStateNotFound", err)
	}
}

func TestService_Complete_StateMismatch(t *testing.T) {
	store := newMockStateStore()
	hasher := token.NewHasher("test-secret-32-bytes-minimum!!!")
	encryptor := token.NewEncryptor("test-secret-32-bytes-minimum!!!")
	service := NewService(store, hasher, encryptor)

	provider := &mockProvider{name: "google"}
	service.RegisterProvider(provider)

	// Store state for a different provider
	store.states["test-state"] = &State{
		State:     "test-state",
		Provider:  "github", // Different provider
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}

	_, _, err := service.Complete(context.Background(), "google", "code", "test-state")
	if !errors.Is(err, ErrStateMismatch) {
		t.Errorf("error = %v, want ErrStateMismatch", err)
	}
}

func TestService_Complete_StateExpired(t *testing.T) {
	store := newMockStateStore()
	hasher := token.NewHasher("test-secret-32-bytes-minimum!!!")
	encryptor := token.NewEncryptor("test-secret-32-bytes-minimum!!!")
	service := NewService(store, hasher, encryptor)

	provider := &mockProvider{name: "test"}
	service.RegisterProvider(provider)

	// Store expired state
	store.states["test-state"] = &State{
		State:     "test-state",
		Provider:  "test",
		ExpiresAt: time.Now().Add(-10 * time.Minute), // Expired
	}

	_, _, err := service.Complete(context.Background(), "test", "code", "test-state")
	if !errors.Is(err, ErrStateExpired) {
		t.Errorf("error = %v, want ErrStateExpired", err)
	}

	// State should be deleted
	if _, exists := store.states["test-state"]; exists {
		t.Error("expired state should be deleted")
	}
}

func TestService_Complete_GetStateError(t *testing.T) {
	store := newMockStateStore()
	store.getErr = errors.New("database error")
	hasher := token.NewHasher("test-secret-32-bytes-minimum!!!")
	encryptor := token.NewEncryptor("test-secret-32-bytes-minimum!!!")
	service := NewService(store, hasher, encryptor)

	provider := &mockProvider{name: "test"}
	service.RegisterProvider(provider)

	_, _, err := service.Complete(context.Background(), "test", "code", "test-state")
	if err == nil {
		t.Error("expected error from store")
	}
}

func TestErrors(t *testing.T) {
	// Test that error variables are defined and have proper messages
	errors := []struct {
		err  error
		want string
	}{
		{ErrProviderNotFound, "oauth provider not found"},
		{ErrStateMismatch, "oauth state mismatch"},
		{ErrStateExpired, "oauth state expired"},
		{ErrStateNotFound, "oauth state not found"},
	}

	for _, e := range errors {
		if e.err.Error() != e.want {
			t.Errorf("error message = %s, want %s", e.err.Error(), e.want)
		}
	}
}

func TestService_Begin_WithRedirectTo(t *testing.T) {
	store := newMockStateStore()
	hasher := token.NewHasher("test-secret-32-bytes-minimum!!!")
	encryptor := token.NewEncryptor("test-secret-32-bytes-minimum!!!")
	service := NewService(store, hasher, encryptor)

	provider := &mockProvider{
		name: "test",
		config: &oauth2.Config{
			ClientID: "client-id",
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://auth.example.com/authorize",
				TokenURL: "https://auth.example.com/token",
			},
		},
	}
	service.RegisterProvider(provider)

	redirectTo := "http://localhost/dashboard"
	_, err := service.Begin(context.Background(), "test", redirectTo)
	if err != nil {
		t.Fatalf("Begin failed: %v", err)
	}

	// Verify redirect is stored in state
	for _, state := range store.states {
		if state.RedirectTo == nil {
			t.Error("RedirectTo should be set")
		} else if *state.RedirectTo != redirectTo {
			t.Errorf("RedirectTo = %s, want %s", *state.RedirectTo, redirectTo)
		}
	}
}

func TestService_Begin_EmptyRedirectTo(t *testing.T) {
	store := newMockStateStore()
	hasher := token.NewHasher("test-secret-32-bytes-minimum!!!")
	encryptor := token.NewEncryptor("test-secret-32-bytes-minimum!!!")
	service := NewService(store, hasher, encryptor)

	provider := &mockProvider{
		name: "test",
		config: &oauth2.Config{
			ClientID: "client-id",
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://auth.example.com/authorize",
				TokenURL: "https://auth.example.com/token",
			},
		},
	}
	service.RegisterProvider(provider)

	_, err := service.Begin(context.Background(), "test", "")
	if err != nil {
		t.Fatalf("Begin failed: %v", err)
	}

	// Verify redirect is nil when empty
	for _, state := range store.states {
		if state.RedirectTo != nil {
			t.Error("RedirectTo should be nil for empty redirect")
		}
	}
}
