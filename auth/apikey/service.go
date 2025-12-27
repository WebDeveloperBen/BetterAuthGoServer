package apikey

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/uptrace/bun"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/kv"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/token"
)

// Service handles API key business logic.
type Service struct {
	db          *bun.DB
	hasher      *token.Hasher
	config      Config
	rateLimiter kv.RateLimiter
	logger      *slog.Logger
}

// NewService creates a new API key service.
func NewService(db *bun.DB, hasher *token.Hasher, config Config, logger *slog.Logger) *Service {
	return &Service{
		db:          db,
		hasher:      hasher,
		config:      config,
		rateLimiter: config.RateLimiter,
		logger:      logger,
	}
}

// Close releases any resources held by the service.
func (s *Service) Close() error {
	if s.rateLimiter != nil {
		return s.rateLimiter.Close()
	}
	return nil
}

// CreateRequest contains the parameters for creating an API key.
type CreateRequest struct {
	Name        *string     `json:"name,omitempty"`
	Prefix      *string     `json:"prefix,omitempty"`
	ExpiresIn   *int64      `json:"expiresIn,omitempty"` // Milliseconds
	Permissions Permissions `json:"permissions,omitempty"`
	Metadata    Metadata    `json:"metadata,omitempty"`

	// Rate limiting overrides
	RateLimitEnabled    *bool  `json:"rateLimitEnabled,omitempty"`
	RateLimitTimeWindow *int64 `json:"rateLimitTimeWindow,omitempty"` // ms
	RateLimitMax        *int   `json:"rateLimitMax,omitempty"`

	// Usage quota
	Remaining      *int   `json:"remaining,omitempty"`
	RefillInterval *int64 `json:"refillInterval,omitempty"` // ms
	RefillAmount   *int   `json:"refillAmount,omitempty"`
}

// CreateResult contains the result of creating an API key.
type CreateResult struct {
	Key    *APIKey `json:"key"`
	RawKey string  `json:"rawKey"` // Only returned on creation
}

// Create generates a new API key for a user.
func (s *Service) Create(ctx context.Context, userID string, req CreateRequest) (*CreateResult, error) {
	// Validate prefix
	if req.Prefix != nil {
		prefix := *req.Prefix
		if len(prefix) < s.config.MinPrefixLength || len(prefix) > s.config.MaxPrefixLength {
			return nil, ErrInvalidPrefix
		}
	}

	// Validate name
	if req.Name != nil {
		name := *req.Name
		if len(name) < s.config.MinNameLength || len(name) > s.config.MaxNameLength {
			return nil, ErrInvalidName
		}
	}

	// Generate random key
	rawKey, err := token.GenerateWithLength(s.config.DefaultKeyLength)
	if err != nil {
		return nil, err
	}

	// Apply prefix if specified
	prefix := req.Prefix
	if prefix == nil && s.config.DefaultPrefix != "" {
		prefix = &s.config.DefaultPrefix
	}

	fullKey := rawKey
	if prefix != nil && *prefix != "" {
		fullKey = *prefix + "_" + rawKey
	}

	// Hash the key (unless disabled)
	var hashedKey string
	if s.config.DisableKeyHashing {
		hashedKey = fullKey
	} else {
		hashedKey = s.hasher.Hash(fullKey)
	}

	// Store first N characters for UI display
	start := rawKey
	if len(start) > s.config.StartLength {
		start = start[:s.config.StartLength]
	}

	// Hash prefix for indexed lookup
	keyPrefix := hashedKey
	if len(keyPrefix) > 8 {
		keyPrefix = keyPrefix[:8]
	}

	// Calculate expiration
	var expiresAt *time.Time
	if req.ExpiresIn != nil {
		exp := time.Now().Add(time.Duration(*req.ExpiresIn) * time.Millisecond)
		expiresAt = &exp
	} else if s.config.DefaultExpiresIn != nil {
		exp := time.Now().Add(*s.config.DefaultExpiresIn)
		expiresAt = &exp
	}

	// Validate expiration limits
	if expiresAt != nil {
		duration := time.Until(*expiresAt)
		if s.config.MinExpiresIn != nil && duration < *s.config.MinExpiresIn {
			exp := time.Now().Add(*s.config.MinExpiresIn)
			expiresAt = &exp
		}
		if s.config.MaxExpiresIn != nil && duration > *s.config.MaxExpiresIn {
			exp := time.Now().Add(*s.config.MaxExpiresIn)
			expiresAt = &exp
		}
	}

	// Serialize permissions
	var permsJSON *string
	perms := req.Permissions
	if perms == nil {
		perms = s.config.DefaultPermissions
	}
	if perms != nil {
		b, err := json.Marshal(perms)
		if err != nil {
			return nil, err
		}
		str := string(b)
		permsJSON = &str
	}

	// Serialize metadata
	var metadataJSON *string
	if req.Metadata != nil && s.config.EnableMetadata {
		b, err := json.Marshal(req.Metadata)
		if err != nil {
			return nil, err
		}
		str := string(b)
		metadataJSON = &str
	}

	// Create API key record
	now := time.Now()
	apiKey := &APIKey{
		ID:        generateID(),
		Name:      req.Name,
		Start:     start,
		Prefix:    prefix,
		Key:       hashedKey,
		KeyPrefix: keyPrefix,
		UserID:    userID,

		RateLimitEnabled:    boolValue(req.RateLimitEnabled, s.config.RateLimitEnabled),
		RateLimitTimeWindow: int64Value(req.RateLimitTimeWindow, int64(s.config.RateLimitTimeWindow.Milliseconds())),
		RateLimitMax:        intValue(req.RateLimitMax, s.config.RateLimitMax),
		RequestCount:        0,

		Remaining:      req.Remaining,
		RefillInterval: req.RefillInterval,
		RefillAmount:   req.RefillAmount,
		LastRefillAt:   nil,

		Enabled:     true,
		LastRequest: nil,
		ExpiresAt:   expiresAt,

		Permissions: permsJSON,
		Metadata:    metadataJSON,

		CreatedAt: now,
		UpdatedAt: now,
	}

	// Insert into database
	_, err = s.db.NewInsert().Model(apiKey).Exec(ctx)
	if err != nil {
		return nil, err
	}

	// Call hook
	if s.config.OnAPIKeyCreated != nil {
		s.config.OnAPIKeyCreated(apiKey)
	}

	return &CreateResult{
		Key:    apiKey,
		RawKey: fullKey,
	}, nil
}

// Get retrieves an API key by ID.
func (s *Service) Get(ctx context.Context, id string) (*APIKey, error) {
	var key APIKey
	err := s.db.NewSelect().
		Model(&key).
		Where("id = ?", id).
		Scan(ctx)
	if err != nil {
		return nil, ErrKeyNotFound
	}
	return &key, nil
}

// GetByIDAndUser retrieves an API key by ID, ensuring it belongs to the user.
func (s *Service) GetByIDAndUser(ctx context.Context, id, userID string) (*APIKey, error) {
	var key APIKey
	err := s.db.NewSelect().
		Model(&key).
		Where("id = ?", id).
		Where("user_id = ?", userID).
		Scan(ctx)
	if err != nil {
		return nil, ErrKeyNotFound
	}
	return &key, nil
}

// List retrieves all API keys for a user.
func (s *Service) List(ctx context.Context, userID string) ([]*APIKey, error) {
	var keys []*APIKey
	err := s.db.NewSelect().
		Model(&keys).
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Scan(ctx)
	if err != nil {
		return nil, err
	}
	return keys, nil
}

// UpdateRequest contains the parameters for updating an API key.
type UpdateRequest struct {
	Name                *string `json:"name,omitempty"`
	Enabled             *bool   `json:"enabled,omitempty"`
	RateLimitEnabled    *bool   `json:"rateLimitEnabled,omitempty"`
	RateLimitTimeWindow *int64  `json:"rateLimitTimeWindow,omitempty"` // ms
	RateLimitMax        *int    `json:"rateLimitMax,omitempty"`
	Remaining           *int    `json:"remaining,omitempty"`
	RefillInterval      *int64  `json:"refillInterval,omitempty"` // ms
	RefillAmount        *int    `json:"refillAmount,omitempty"`
	ExpiresIn           *int64  `json:"expiresIn,omitempty"` // ms from now
}

// Update modifies an API key.
func (s *Service) Update(ctx context.Context, id, userID string, req UpdateRequest) (*APIKey, error) {
	key, err := s.GetByIDAndUser(ctx, id, userID)
	if err != nil {
		return nil, err
	}

	// Apply updates
	if req.Name != nil {
		if len(*req.Name) < s.config.MinNameLength || len(*req.Name) > s.config.MaxNameLength {
			return nil, ErrInvalidName
		}
		key.Name = req.Name
	}
	if req.Enabled != nil {
		key.Enabled = *req.Enabled
	}
	if req.RateLimitEnabled != nil {
		key.RateLimitEnabled = *req.RateLimitEnabled
	}
	if req.RateLimitTimeWindow != nil {
		key.RateLimitTimeWindow = *req.RateLimitTimeWindow
	}
	if req.RateLimitMax != nil {
		key.RateLimitMax = *req.RateLimitMax
	}
	if req.Remaining != nil {
		key.Remaining = req.Remaining
	}
	if req.RefillInterval != nil {
		key.RefillInterval = req.RefillInterval
	}
	if req.RefillAmount != nil {
		key.RefillAmount = req.RefillAmount
	}
	if req.ExpiresIn != nil {
		exp := time.Now().Add(time.Duration(*req.ExpiresIn) * time.Millisecond)
		key.ExpiresAt = &exp
	}

	key.UpdatedAt = time.Now()

	// Update in database
	_, err = s.db.NewUpdate().
		Model(key).
		WherePK().
		Exec(ctx)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// Delete removes an API key.
func (s *Service) Delete(ctx context.Context, id, userID string) error {
	key, err := s.GetByIDAndUser(ctx, id, userID)
	if err != nil {
		return err
	}

	_, err = s.db.NewDelete().
		Model((*APIKey)(nil)).
		Where("id = ?", id).
		Exec(ctx)
	if err != nil {
		return err
	}

	// Call hook
	if s.config.OnAPIKeyDeleted != nil {
		s.config.OnAPIKeyDeleted(key)
	}

	return nil
}

// DeleteAllExpired removes all expired API keys.
func (s *Service) DeleteAllExpired(ctx context.Context) (int64, error) {
	res, err := s.db.NewDelete().
		Model((*APIKey)(nil)).
		Where("expires_at IS NOT NULL").
		Where("expires_at < ?", time.Now()).
		Exec(ctx)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// VerifyKey validates an API key and returns the key if valid.
func (s *Service) VerifyKey(ctx context.Context, rawKey string, requiredPerms Permissions) (*APIKey, error) {
	// Hash the incoming key
	var hashedKey string
	if s.config.DisableKeyHashing {
		hashedKey = rawKey
	} else {
		hashedKey = s.hasher.Hash(rawKey)
	}

	keyPrefix := hashedKey
	if len(keyPrefix) > 8 {
		keyPrefix = keyPrefix[:8]
	}

	// Query by hash prefix (fast indexed lookup)
	var candidates []*APIKey
	err := s.db.NewSelect().
		Model(&candidates).
		Where("key_prefix = ?", keyPrefix).
		Where("enabled = ?", true).
		Scan(ctx)
	if err != nil {
		return nil, ErrInvalidAPIKey
	}

	// Find exact match using constant-time compare
	var key *APIKey
	for _, k := range candidates {
		if subtle.ConstantTimeCompare([]byte(k.Key), []byte(hashedKey)) == 1 {
			key = k
			break
		}
	}
	if key == nil {
		return nil, ErrInvalidAPIKey
	}

	// Check if disabled
	if !key.Enabled {
		return nil, ErrDisabledAPIKey
	}

	// Check expiration
	if key.ExpiresAt != nil && key.ExpiresAt.Before(time.Now()) {
		return nil, ErrExpiredAPIKey
	}

	// Check rate limit
	allowed, retryAfter, err := s.checkRateLimit(ctx, key)
	if err != nil {
		s.logger.Error("rate limit check error", "error", err)
	}
	if !allowed {
		return nil, &RateLimitError{RetryAfter: retryAfter}
	}

	// Check and refill remaining
	if err := s.checkAndRefillRemaining(key); err != nil {
		return nil, err
	}

	// Check permissions
	if requiredPerms != nil {
		if err := s.checkPermissions(key, requiredPerms); err != nil {
			return nil, err
		}
	}

	// Update usage stats
	if err := s.updateUsageStats(ctx, key); err != nil {
		s.logger.Error("failed to update usage stats", "error", err, "key_id", key.ID)
	}

	return key, nil
}

// checkRateLimit uses either kv.RateLimiter or database-based limiting.
func (s *Service) checkRateLimit(ctx context.Context, key *APIKey) (allowed bool, retryAfter time.Duration, err error) {
	if !key.RateLimitEnabled {
		return true, 0, nil
	}

	window := time.Duration(key.RateLimitTimeWindow) * time.Millisecond
	if window == 0 {
		window = s.config.RateLimitTimeWindow
	}
	limit := key.RateLimitMax
	if limit == 0 {
		limit = s.config.RateLimitMax
	}

	// Mode 2: Use external kv.RateLimiter if configured
	if s.rateLimiter != nil {
		result, err := s.rateLimiter.Allow(ctx, kv.Key(kv.PrefixPlugin, "apikey:rl:"+key.ID), limit, window, 1)
		if err != nil {
			return true, 0, nil // Fail open on error
		}
		if !result.Allowed {
			return false, time.Until(result.ResetAt), nil
		}
		return true, 0, nil
	}

	// Mode 1: Database-based (default, matches better-auth)
	return s.checkRateLimitDB(key, limit, window)
}

// checkRateLimitDB implements fixed-window rate limiting in the database.
func (s *Service) checkRateLimitDB(key *APIKey, limit int, window time.Duration) (bool, time.Duration, error) {
	now := time.Now()

	// Check if we're in a new window
	if key.LastRequest != nil {
		elapsed := now.Sub(*key.LastRequest)
		if elapsed >= window {
			// New window - reset counter
			key.RequestCount = 1
			return true, 0, nil
		}
	} else {
		// First request ever
		key.RequestCount = 1
		return true, 0, nil
	}

	// Check if at limit
	if key.RequestCount >= limit {
		retryAfter := window - now.Sub(*key.LastRequest)
		return false, retryAfter, nil
	}

	key.RequestCount++
	return true, 0, nil
}

// checkAndRefillRemaining checks the remaining count and refills if needed.
func (s *Service) checkAndRefillRemaining(key *APIKey) error {
	// Check if refill is needed
	if key.RefillInterval != nil && key.RefillAmount != nil {
		refillDuration := time.Duration(*key.RefillInterval) * time.Millisecond
		lastRefill := key.CreatedAt
		if key.LastRefillAt != nil {
			lastRefill = *key.LastRefillAt
		}

		if time.Since(lastRefill) >= refillDuration {
			key.Remaining = key.RefillAmount
			now := time.Now()
			key.LastRefillAt = &now
		}
	}

	// Check remaining count
	if key.Remaining != nil {
		if *key.Remaining <= 0 {
			return ErrNoRemainingUses
		}
		*key.Remaining--
	}

	return nil
}

// checkPermissions verifies the key has all required permissions.
func (s *Service) checkPermissions(key *APIKey, required Permissions) error {
	if required == nil {
		return nil
	}

	var keyPerms Permissions
	if key.Permissions != nil {
		if err := json.Unmarshal([]byte(*key.Permissions), &keyPerms); err != nil {
			return ErrInsufficientPerms
		}
	}

	if !keyPerms.HasAllPermissions(required) {
		return ErrInsufficientPerms
	}

	return nil
}

// updateUsageStats updates the last request time and request count.
func (s *Service) updateUsageStats(ctx context.Context, key *APIKey) error {
	now := time.Now()
	key.LastRequest = &now
	key.UpdatedAt = now

	_, err := s.db.NewUpdate().
		Model(key).
		Column("last_request", "request_count", "remaining", "last_refill_at", "updated_at").
		WherePK().
		Exec(ctx)
	return err
}

// GetPermissions parses and returns the key's permissions.
func (s *Service) GetPermissions(key *APIKey) (Permissions, error) {
	if key.Permissions == nil {
		return nil, nil
	}
	var perms Permissions
	if err := json.Unmarshal([]byte(*key.Permissions), &perms); err != nil {
		return nil, err
	}
	return perms, nil
}

// GetMetadata parses and returns the key's metadata.
func (s *Service) GetMetadata(key *APIKey) (Metadata, error) {
	if key.Metadata == nil {
		return nil, nil
	}
	var meta Metadata
	if err := json.Unmarshal([]byte(*key.Metadata), &meta); err != nil {
		return nil, err
	}
	return meta, nil
}

// Helper functions

func generateID() string {
	id, _ := token.GenerateWithLength(16)
	return id
}

func boolValue(ptr *bool, def bool) bool {
	if ptr != nil {
		return *ptr
	}
	return def
}

func intValue(ptr *int, def int) int {
	if ptr != nil {
		return *ptr
	}
	return def
}

func int64Value(ptr *int64, def int64) int64 {
	if ptr != nil {
		return *ptr
	}
	return def
}
