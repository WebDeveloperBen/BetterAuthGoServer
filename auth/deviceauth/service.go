package deviceauth

import (
	"context"
	"crypto/rand"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/token"
)

// userCodeCharset excludes ambiguous characters: 0/O, 1/I/L
const userCodeCharset = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// deviceCodeCharset includes alphanumeric characters
const deviceCodeCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// Service handles device authorization business logic.
type Service struct {
	store  DeviceCodeStore
	hasher *token.Hasher
	config Config
	logger *slog.Logger

	// Cleanup goroutine management
	stopCleanup chan struct{}
	wg          sync.WaitGroup
}

// NewService creates a new device authorization service.
func NewService(store DeviceCodeStore, hasher *token.Hasher, config Config, logger *slog.Logger) *Service {
	s := &Service{
		store:       store,
		hasher:      hasher,
		config:      config,
		logger:      logger,
		stopCleanup: make(chan struct{}),
	}

	// Start cleanup goroutine if interval is set
	if config.CleanupInterval > 0 {
		s.wg.Add(1)
		go s.cleanupLoop()
	}

	return s
}

// Close stops the service and cleanup goroutine.
func (s *Service) Close() error {
	close(s.stopCleanup)
	s.wg.Wait()
	return nil
}

// CreateDeviceCodeRequest contains the parameters for creating a device code.
type CreateDeviceCodeRequest struct {
	ClientID string
	Scope    string
}

// CreateDeviceCodeResult contains the generated codes and metadata.
type CreateDeviceCodeResult struct {
	// DeviceCode is the raw (unhashed) device code to return to the client.
	DeviceCode string

	// UserCode is the human-readable code for the user.
	UserCode string

	// VerificationURI is the URL where users enter the code.
	VerificationURI string

	// VerificationURIComplete includes the user_code in the URL.
	VerificationURIComplete string

	// ExpiresIn is the lifetime in seconds.
	ExpiresIn int

	// Interval is the minimum polling interval in seconds.
	Interval int
}

// CreateDeviceCode generates a new device code and user code.
func (s *Service) CreateDeviceCode(ctx context.Context, req CreateDeviceCodeRequest) (*CreateDeviceCodeResult, error) {
	// Validate client if validator is configured
	if s.config.ValidateClient != nil {
		if err := s.config.ValidateClient(ctx, req.ClientID); err != nil {
			return nil, err
		}
	}

	// Generate device code
	var rawDeviceCode string
	if s.config.GenerateDeviceCode != nil {
		rawDeviceCode = s.config.GenerateDeviceCode()
	} else {
		rawDeviceCode = generateRandomString(s.config.DeviceCodeLength, deviceCodeCharset)
	}

	// Generate user code
	var userCode string
	if s.config.GenerateUserCode != nil {
		userCode = s.config.GenerateUserCode()
	} else {
		userCode = generateUserCode(s.config.UserCodeLength)
	}

	// Hash the device code for storage
	hashedDeviceCode := s.hasher.Hash(rawDeviceCode)

	// Create device code record
	now := time.Now()
	var clientID, scope *string
	if req.ClientID != "" {
		clientID = &req.ClientID
	}
	if req.Scope != "" {
		scope = &req.Scope
	}

	dc := &DeviceCode{
		ID:              uuid.NewString(),
		DeviceCode:      hashedDeviceCode,
		DeviceCodeHash:  hashedDeviceCode[:8], // First 8 chars for indexed lookup
		UserCode:        userCode,
		ClientID:        clientID,
		Scope:           scope,
		Status:          StatusPending,
		PollingInterval: s.config.PollingInterval,
		ExpiresAt:       now.Add(s.config.ExpiresIn),
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	// Insert into database
	if err := s.store.CreateDeviceCode(ctx, dc); err != nil {
		s.logger.Error("failed to insert device code", "error", err)
		return nil, err
	}

	// Call hook if configured
	if s.config.OnDeviceAuthRequest != nil {
		if err := s.config.OnDeviceAuthRequest(ctx, dc); err != nil {
			s.logger.Error("OnDeviceAuthRequest hook failed", "error", err)
			// Don't fail the request, just log
		}
	}

	s.logger.Info("created device code",
		"device_code_id", dc.ID,
		"user_code", userCode,
		"client_id", req.ClientID,
		"expires_at", dc.ExpiresAt,
	)

	// Build verification URI
	verificationURI := s.config.VerificationURI
	verificationURIComplete := verificationURI + "?user_code=" + userCode

	return &CreateDeviceCodeResult{
		DeviceCode:              rawDeviceCode,
		UserCode:                userCode,
		VerificationURI:         verificationURI,
		VerificationURIComplete: verificationURIComplete,
		ExpiresIn:               int(s.config.ExpiresIn.Seconds()),
		Interval:                s.config.PollingInterval,
	}, nil
}

// GetByUserCode retrieves a device code by its user code.
func (s *Service) GetByUserCode(ctx context.Context, userCode string) (*DeviceCode, error) {
	dc, err := s.store.GetDeviceCodeByUserCode(ctx, userCode)
	if err != nil {
		return nil, ErrInvalidUserCode
	}
	if dc == nil {
		return nil, ErrInvalidUserCode
	}

	if dc.IsExpired() {
		return nil, ErrExpiredUserCode
	}

	return dc, nil
}

// GetByDeviceCode retrieves a device code by its raw device code.
func (s *Service) GetByDeviceCode(ctx context.Context, rawDeviceCode string) (*DeviceCode, error) {
	hashedCode := s.hasher.Hash(rawDeviceCode)
	hashPrefix := hashedCode[:8]

	dc, err := s.store.GetDeviceCodeByHash(ctx, hashPrefix, hashedCode)
	if err != nil {
		return nil, ErrInvalidDeviceCode
	}
	if dc == nil {
		return nil, ErrInvalidDeviceCode
	}

	return dc, nil
}

// Approve marks a device code as approved by the given user.
func (s *Service) Approve(ctx context.Context, userCode string, userID string) error {
	dc, err := s.GetByUserCode(ctx, userCode)
	if err != nil {
		return err
	}

	if !dc.IsPending() {
		return ErrAlreadyProcessed
	}

	err = s.store.UpdateDeviceCodeStatus(ctx, dc.ID, string(StatusApproved), &userID)
	if err != nil {
		s.logger.Error("failed to approve device code", "error", err, "device_code_id", dc.ID)
		return err
	}

	s.logger.Info("approved device code",
		"device_code_id", dc.ID,
		"user_code", dc.UserCode,
		"user_id", userID,
	)

	return nil
}

// Deny marks a device code as denied.
func (s *Service) Deny(ctx context.Context, userCode string) error {
	dc, err := s.GetByUserCode(ctx, userCode)
	if err != nil {
		return err
	}

	if !dc.IsPending() {
		return ErrAlreadyProcessed
	}

	err = s.store.UpdateDeviceCodeStatus(ctx, dc.ID, string(StatusDenied), nil)
	if err != nil {
		s.logger.Error("failed to deny device code", "error", err, "device_code_id", dc.ID)
		return err
	}

	s.logger.Info("denied device code",
		"device_code_id", dc.ID,
		"user_code", dc.UserCode,
	)

	return nil
}

// CheckTokenResult contains the result of a token check.
type CheckTokenResult struct {
	// Approved is true if the device code was approved.
	Approved bool

	// UserID is the user who approved (only set if approved).
	UserID string

	// DeviceCode is the device code record.
	DeviceCode *DeviceCode
}

// CheckToken checks if a device code has been approved.
// This is called when the device polls for a token.
func (s *Service) CheckToken(ctx context.Context, rawDeviceCode string, clientID string) (*CheckTokenResult, error) {
	dc, err := s.GetByDeviceCode(ctx, rawDeviceCode)
	if err != nil {
		return nil, err
	}

	// Check expiration
	if dc.IsExpired() {
		return nil, ErrExpiredDeviceCode
	}

	// Check client_id match if provided
	if dc.ClientID != nil && *dc.ClientID != clientID {
		return nil, ErrInvalidClient
	}

	// Check rate limiting
	if !dc.CanPoll() {
		return nil, ErrSlowDown
	}

	// Update last polled time
	now := time.Now()
	err = s.store.UpdateDeviceCodeLastPolled(ctx, dc.ID, now)
	if err != nil {
		s.logger.Error("failed to update last_polled_at", "error", err)
		// Continue anyway
	}

	// Check status
	switch dc.Status {
	case StatusApproved:
		if dc.UserID == nil {
			return nil, ErrInvalidDeviceCode
		}
		return &CheckTokenResult{
			Approved:   true,
			UserID:     *dc.UserID,
			DeviceCode: dc,
		}, nil

	case StatusDenied:
		return nil, ErrAccessDenied

	case StatusPending:
		return nil, ErrAuthorizationPending

	default:
		return nil, ErrInvalidDeviceCode
	}
}

// CleanupExpired removes expired device codes.
func (s *Service) CleanupExpired(ctx context.Context) (int64, error) {
	return s.store.DeleteExpiredDeviceCodes(ctx)
}

// cleanupLoop runs the cleanup job at the configured interval.
func (s *Service) cleanupLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.CleanupInterval)
	defer ticker.Stop()

	s.logger.Info("started device code cleanup loop",
		"interval", s.config.CleanupInterval,
	)

	for {
		select {
		case <-s.stopCleanup:
			s.logger.Info("stopping device code cleanup loop")
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			count, err := s.CleanupExpired(ctx)
			cancel()

			if err != nil {
				s.logger.Error("failed to cleanup expired device codes", "error", err)
			} else if count > 0 {
				s.logger.Info("cleaned up expired device codes", "count", count)
			}
		}
	}
}

// Helper functions

// generateRandomString generates a cryptographically secure random string.
func generateRandomString(length int, charset string) string {
	result := make([]byte, length)
	for i := range result {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			panic(err) // Should never happen with crypto/rand
		}
		result[i] = charset[n.Int64()]
	}
	return string(result)
}

// generateUserCode generates a user-friendly code with a hyphen in the middle.
func generateUserCode(length int) string {
	code := generateRandomString(length, userCodeCharset)
	// Insert hyphen in the middle
	mid := len(code) / 2
	return code[:mid] + "-" + code[mid:]
}

// normalizeUserCode removes hyphens and converts to uppercase.
func normalizeUserCode(code string) string {
	result := make([]byte, 0, len(code))
	for i := 0; i < len(code); i++ {
		c := code[i]
		if c != '-' && c != ' ' {
			// Convert to uppercase
			if c >= 'a' && c <= 'z' {
				c = c - 'a' + 'A'
			}
			result = append(result, c)
		}
	}
	return string(result)
}
