package password

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// Service errors.
var (
	ErrUserAlreadyExists    = errors.New("user already exists")
	ErrInvalidCredentials   = errors.New("invalid email or password")
	ErrAccountNotFound      = errors.New("email account not found")
	ErrOTPPluginNotFound    = errors.New("otp plugin not configured")
	ErrVerificationNotFound = errors.New("verification token not found or expired")
	ErrVerificationExpired  = errors.New("verification token has expired")
)

// TokenType for password reset tokens.
const TokenTypePasswordReset = "password_reset"

// Service handles password authentication operations.
type Service struct {
	db       *bun.DB
	hasher   PasswordHasher
	auth     AuthProvider
	otp      OTPService
	eventBus models.EventBus
	config   Config
	logger   *slog.Logger
}

// NewService creates a new password service.
func NewService(
	db *bun.DB,
	auth AuthProvider,
	otp OTPService,
	eventBus models.EventBus,
	config Config,
	logger *slog.Logger,
) *Service {
	return &Service{
		db:       db,
		hasher:   NewArgon2PasswordHasher(),
		auth:     auth,
		otp:      otp,
		eventBus: eventBus,
		config:   config,
		logger:   logger,
	}
}

// SignUp creates a new user with email/password authentication.
func (s *Service) SignUp(ctx context.Context, email, password, name string, r *http.Request) (*plugin.User, *plugin.Session, error) {
	// Validate password
	if err := ValidatePassword(password, s.config); err != nil {
		return nil, nil, err
	}

	// Check if user already exists
	existing, err := s.auth.GetPluginUserByEmail(ctx, email)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return nil, nil, err
	}
	if existing != nil {
		return nil, nil, ErrUserAlreadyExists
	}

	// Hash password
	passwordHash, err := s.hasher.Hash(password)
	if err != nil {
		return nil, nil, err
	}

	// Create user via auth provider
	user, err := s.auth.CreatePluginUser(ctx, plugin.CreateUserRequest{
		Email:         email,
		Name:          name,
		EmailVerified: false,
	})
	if err != nil {
		return nil, nil, err
	}

	// Create email account in database
	if err := s.createEmailAccount(ctx, user.ID, passwordHash); err != nil {
		// Note: User was already created, but account creation failed
		// This is a partial failure that should be logged
		s.logger.Error("failed to create email account after user creation",
			"user_id", user.ID,
			"error", err,
		)
		return nil, nil, err
	}

	// Auto sign-in if enabled
	var session *plugin.Session
	if s.config.AutoSignIn {
		session, err = s.auth.CreateSessionForUser(ctx, user.ID, r)
		if err != nil {
			s.logger.Error("failed to create session after signup",
				"user_id", user.ID,
				"error", err,
			)
			// Don't fail the signup, just return without session
		}
	}

	return user, session, nil
}

// SignIn authenticates a user with email/password.
func (s *Service) SignIn(ctx context.Context, email, password string, r *http.Request) (*plugin.User, *plugin.Session, error) {
	// Get user - use constant time comparison to prevent timing attacks
	user, err := s.auth.GetPluginUserByEmail(ctx, email)
	if err != nil {
		// Still hash the password to prevent timing attacks
		_, _ = s.hasher.Hash(password)
		if errors.Is(err, ErrUserNotFound) {
			return nil, nil, ErrInvalidCredentials
		}
		return nil, nil, err
	}

	// Get email account
	account, err := s.getEmailAccount(ctx, user.ID)
	if err != nil || account == nil || account.PasswordHash == nil {
		return nil, nil, ErrInvalidCredentials
	}

	// Verify password
	if !s.hasher.Verify(password, *account.PasswordHash) {
		return nil, nil, ErrInvalidCredentials
	}

	// Create session
	session, err := s.auth.CreateSessionForUser(ctx, user.ID, r)
	if err != nil {
		return nil, nil, err
	}

	return user, session, nil
}

// ChangePassword changes a user's password (requires current password).
func (s *Service) ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error {
	// Validate new password
	if err := ValidatePassword(newPassword, s.config); err != nil {
		return err
	}

	// Verify old password
	ok, err := s.auth.VerifyPassword(ctx, userID, oldPassword)
	if err != nil {
		return err
	}
	if !ok {
		return ErrInvalidCredentials
	}

	// Update password
	return s.updatePassword(ctx, userID, newPassword)
}

// RequestPasswordReset initiates a password reset flow.
func (s *Service) RequestPasswordReset(ctx context.Context, email string) error {
	// Check if OTP service is available
	if s.otp == nil {
		return ErrOTPPluginNotFound
	}

	// Get user - don't reveal if user exists
	user, err := s.auth.GetPluginUserByEmail(ctx, email)
	if err != nil || user == nil {
		// Don't reveal if user exists or not
		return nil
	}

	// Create password reset token
	_, err = s.otp.CreateToken(ctx, user.ID, TokenTypePasswordReset)
	if err != nil {
		return err
	}

	// Note: The event publishing is handled by auth.go which listens for token creation
	// and publishes EventPasswordResetRequested

	return nil
}

// ConfirmPasswordReset completes a password reset.
func (s *Service) ConfirmPasswordReset(ctx context.Context, token, newPassword string) error {
	// Check if OTP service is available
	if s.otp == nil {
		return ErrOTPPluginNotFound
	}

	// Validate new password
	if err := ValidatePassword(newPassword, s.config); err != nil {
		return err
	}

	// Consume the token
	otpToken, err := s.otp.ConsumeToken(ctx, token, TokenTypePasswordReset)
	if err != nil {
		// Map OTP errors to more user-friendly errors
		return s.mapOTPError(err)
	}

	// Update password
	if err := s.updatePassword(ctx, otpToken.UserID, newPassword); err != nil {
		return err
	}

	// Invalidate all sessions for security
	// This is handled by deleting sessions through the store
	return s.deleteUserSessions(ctx, otpToken.UserID)
}

// ErrUserNotFound is returned when a user is not found.
var ErrUserNotFound = errors.New("user not found")

// createEmailAccount creates an email account for a user.
func (s *Service) createEmailAccount(ctx context.Context, userID, passwordHash string) error {
	now := time.Now()
	account := &Account{
		ID:           uuid.New().String(),
		UserID:       userID,
		Provider:     ProviderEmail,
		PasswordHash: &passwordHash,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	_, err := s.db.NewInsert().
		Model(account).
		Exec(ctx)
	return err
}

// getEmailAccount retrieves the email account for a user.
func (s *Service) getEmailAccount(ctx context.Context, userID string) (*Account, error) {
	var account Account
	err := s.db.NewSelect().
		Model(&account).
		Where("user_id = ?", userID).
		Where("provider = ?", ProviderEmail).
		Scan(ctx)
	if err != nil {
		return nil, err
	}
	return &account, nil
}

// updatePassword updates a user's password hash.
func (s *Service) updatePassword(ctx context.Context, userID, newPassword string) error {
	// Hash the new password
	passwordHash, err := s.hasher.Hash(newPassword)
	if err != nil {
		return err
	}

	// Update the account
	_, err = s.db.NewUpdate().
		Model((*Account)(nil)).
		Set("password_hash = ?", passwordHash).
		Set("updated_at = ?", time.Now()).
		Where("user_id = ?", userID).
		Where("provider = ?", ProviderEmail).
		Exec(ctx)
	return err
}

// deleteUserSessions deletes all sessions for a user.
func (s *Service) deleteUserSessions(ctx context.Context, userID string) error {
	_, err := s.db.NewDelete().
		Model((*Session)(nil)).
		Where("user_id = ?", userID).
		Exec(ctx)
	return err
}

// mapOTPError maps OTP errors to password service errors.
func (s *Service) mapOTPError(err error) error {
	errStr := err.Error()
	switch {
	case errStr == "token not found":
		return ErrVerificationNotFound
	case errStr == "token expired":
		return ErrVerificationExpired
	default:
		return err
	}
}

// Account represents an email account in the database.
// This mirrors models.Account but is used for direct DB access.
type Account struct {
	bun.BaseModel `bun:"table:accounts,alias:a"`

	ID           string    `bun:"id,pk"`
	UserID       string    `bun:"user_id,notnull"`
	Provider     string    `bun:"provider,notnull"`
	PasswordHash *string   `bun:"password_hash"`
	CreatedAt    time.Time `bun:"created_at,notnull"`
	UpdatedAt    time.Time `bun:"updated_at,notnull"`
}

// Session represents a session in the database.
// This mirrors models.Session but is used for direct DB access.
type Session struct {
	bun.BaseModel `bun:"table:sessions,alias:s"`

	ID     string `bun:"id,pk"`
	UserID string `bun:"user_id,notnull"`
}

// ProviderEmail is the provider type for email/password auth.
const ProviderEmail = "email"
