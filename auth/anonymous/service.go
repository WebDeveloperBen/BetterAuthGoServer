package anonymous

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// Service provides anonymous authentication functionality
type Service struct {
	db     *bun.DB
	auth   AuthProvider
	config Config
	logger *slog.Logger

	// Cleanup goroutine management
	stopCleanup chan struct{}
	cleanupWg   sync.WaitGroup
}

// NewService creates a new anonymous service
func NewService(db *bun.DB, auth AuthProvider, config Config, logger *slog.Logger) *Service {
	s := &Service{
		db:          db,
		auth:        auth,
		config:      config,
		logger:      logger,
		stopCleanup: make(chan struct{}),
	}

	// Start cleanup goroutine if TTL is configured
	if config.AnonymousUserTTL > 0 {
		s.startCleanupLoop()
	}

	return s
}

// Close stops the cleanup goroutine
func (s *Service) Close() error {
	if s.config.AnonymousUserTTL > 0 {
		close(s.stopCleanup)
		s.cleanupWg.Wait()
	}
	return nil
}

// CreateAnonymousUser creates a new anonymous user and session.
// Returns the local User type which includes the IsAnonymous field.
func (s *Service) CreateAnonymousUser(ctx context.Context, r *http.Request) (*User, *plugin.Session, error) {
	// Generate email
	email := s.generateEmail()

	// Generate name
	name := s.generateName()

	// Create the user via the auth provider
	pluginUser, err := s.auth.CreatePluginUser(ctx, plugin.CreateUserRequest{
		Email:         email,
		Name:          name,
		EmailVerified: false, // Anonymous users have unverified emails
	})
	if err != nil {
		s.logger.Error("failed to create anonymous user", "error", err)
		return nil, nil, fmt.Errorf("%w: %v", ErrUserCreation, err)
	}

	// Set is_anonymous flag via direct DB update
	// (CreatePluginUser doesn't support is_anonymous in the request)
	if err := s.setAnonymousFlag(ctx, pluginUser.ID, true); err != nil {
		s.logger.Error("failed to set anonymous flag", "error", err, "user_id", pluginUser.ID)
		// Clean up the user we just created
		_ = s.auth.DeleteUser(ctx, pluginUser.ID)
		return nil, nil, fmt.Errorf("%w: %v", ErrUserCreation, err)
	}

	// Create our local User type with IsAnonymous = true
	user := &User{
		ID:            pluginUser.ID,
		Email:         pluginUser.Email,
		EmailVerified: pluginUser.EmailVerified,
		Name:          pluginUser.Name,
		Image:         pluginUser.Image,
		Role:          pluginUser.Role,
		Banned:        pluginUser.Banned,
		IsAnonymous:   true,
		CreatedAt:     pluginUser.CreatedAt,
		UpdatedAt:     pluginUser.UpdatedAt,
	}

	// Create session
	session, err := s.auth.CreateSessionForUser(ctx, user.ID, r)
	if err != nil {
		s.logger.Error("failed to create session for anonymous user", "error", err, "user_id", user.ID)
		// Clean up the user we just created
		_ = s.auth.DeleteUser(ctx, user.ID)
		return nil, nil, fmt.Errorf("%w: %v", ErrSessionCreation, err)
	}

	s.logger.Info("created anonymous user", "user_id", user.ID, "email", email)

	return user, session, nil
}

// HandleAccountLink handles the account linking when an anonymous user signs in with real credentials
func (s *Service) HandleAccountLink(ctx context.Context, anonUser, newUser *plugin.User) error {
	s.logger.Info("linking anonymous account",
		"anonymous_user_id", anonUser.ID,
		"new_user_id", newUser.ID,
	)

	// Call the OnLinkAccount callback if configured
	if s.config.OnLinkAccount != nil {
		if err := s.config.OnLinkAccount(ctx, anonUser, newUser); err != nil {
			s.logger.Error("OnLinkAccount callback failed",
				"error", err,
				"anonymous_user_id", anonUser.ID,
				"new_user_id", newUser.ID,
			)
			return err
		}
	}

	// Delete the anonymous user unless configured to keep it
	if !s.config.DisableDeleteAnonymousUser {
		if err := s.auth.DeleteUser(ctx, anonUser.ID); err != nil {
			s.logger.Error("failed to delete anonymous user after linking",
				"error", err,
				"anonymous_user_id", anonUser.ID,
			)
			// Don't return error - the link was successful, just cleanup failed
		} else {
			s.logger.Info("deleted anonymous user after linking", "anonymous_user_id", anonUser.ID)
		}
	}

	return nil
}

// generateEmail generates an email address for an anonymous user
func (s *Service) generateEmail() string {
	if s.config.GenerateEmail != nil {
		return s.config.GenerateEmail()
	}
	return fmt.Sprintf("anon-%s@%s", uuid.New().String()[:8], s.config.EmailDomain)
}

// generateName generates a display name for an anonymous user
func (s *Service) generateName() string {
	if s.config.GenerateName != nil {
		return s.config.GenerateName()
	}
	return "Anonymous User"
}

// setAnonymousFlag updates the is_anonymous flag for a user
func (s *Service) setAnonymousFlag(ctx context.Context, userID string, isAnonymous bool) error {
	_, err := s.db.NewUpdate().
		Table("users").
		Set("is_anonymous = ?", isAnonymous).
		Set("updated_at = ?", time.Now()).
		Where("id = ?", userID).
		Exec(ctx)
	return err
}

// startCleanupLoop starts the background cleanup goroutine
func (s *Service) startCleanupLoop() {
	s.cleanupWg.Add(1)
	go func() {
		defer s.cleanupWg.Done()

		ticker := time.NewTicker(s.config.CleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-s.stopCleanup:
				return
			case <-ticker.C:
				if err := s.cleanupStaleAnonymousUsers(context.Background()); err != nil {
					s.logger.Error("failed to cleanup stale anonymous users", "error", err)
				}
			}
		}
	}()

	s.logger.Info("started anonymous user cleanup loop",
		"ttl", s.config.AnonymousUserTTL,
		"interval", s.config.CleanupInterval,
	)
}

// cleanupStaleAnonymousUsers deletes anonymous users older than the configured TTL
func (s *Service) cleanupStaleAnonymousUsers(ctx context.Context) error {
	cutoff := time.Now().Add(-s.config.AnonymousUserTTL)

	result, err := s.db.NewDelete().
		Table("users").
		Where("is_anonymous = ?", true).
		Where("created_at < ?", cutoff).
		Exec(ctx)
	if err != nil {
		return err
	}

	affected, _ := result.RowsAffected()
	if affected > 0 {
		s.logger.Info("cleaned up stale anonymous users", "count", affected)
	}

	return nil
}
