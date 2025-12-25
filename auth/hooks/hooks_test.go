package hooks

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
)

func TestHooks_Fire_NilFn(t *testing.T) {
	h := &Hooks{}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	// Should not panic when fn is nil
	h.fire(context.Background(), logger, "TestHook", nil)

	// No error should be logged
	if buf.Len() > 0 {
		t.Errorf("no output expected for nil fn, got: %s", buf.String())
	}
}

func TestHooks_Fire_SuccessfulFn(t *testing.T) {
	h := &Hooks{}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	called := false
	h.fire(context.Background(), logger, "TestHook", func() error {
		called = true
		return nil
	})

	if !called {
		t.Error("function should have been called")
	}
	if buf.Len() > 0 {
		t.Errorf("no output expected for successful fn, got: %s", buf.String())
	}
}

func TestHooks_Fire_ErrorFn(t *testing.T) {
	h := &Hooks{}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	h.fire(context.Background(), logger, "TestHook", func() error {
		return errors.New("hook error")
	})

	output := buf.String()
	if !strings.Contains(output, "hook failed") {
		t.Error("expected 'hook failed' in output")
	}
	if !strings.Contains(output, "TestHook") {
		t.Error("expected hook name in output")
	}
	if !strings.Contains(output, "hook error") {
		t.Error("expected error message in output")
	}
}

func TestHooks_FireUserCreated_NilHook(t *testing.T) {
	h := &Hooks{}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	// Should not panic with nil hook
	h.FireUserCreated(context.Background(), logger, &models.User{ID: "user-123"})
}

func TestHooks_FireUserCreated_WithHook(t *testing.T) {
	var capturedUser *models.User
	h := &Hooks{
		OnUserCreated: func(ctx context.Context, user *models.User) error {
			capturedUser = user
			return nil
		},
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	user := &models.User{ID: "user-123", Email: "test@example.com"}
	h.FireUserCreated(context.Background(), logger, user)

	if capturedUser == nil {
		t.Fatal("hook should have been called")
	}
	if capturedUser.ID != "user-123" {
		t.Errorf("capturedUser.ID = %s, want user-123", capturedUser.ID)
	}
}

func TestHooks_FireUserCreated_Error(t *testing.T) {
	h := &Hooks{
		OnUserCreated: func(ctx context.Context, user *models.User) error {
			return errors.New("user creation hook failed")
		},
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	h.FireUserCreated(context.Background(), logger, &models.User{ID: "user-123"})

	output := buf.String()
	if !strings.Contains(output, "OnUserCreated") {
		t.Error("expected hook name in error output")
	}
}

func TestHooks_FireUserUpdated_NilHook(t *testing.T) {
	h := &Hooks{}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	// Should not panic with nil hook
	h.FireUserUpdated(context.Background(), logger, &models.User{ID: "user-123"})
}

func TestHooks_FireUserUpdated_WithHook(t *testing.T) {
	var capturedUser *models.User
	h := &Hooks{
		OnUserUpdated: func(ctx context.Context, user *models.User) error {
			capturedUser = user
			return nil
		},
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	user := &models.User{ID: "user-456", Email: "updated@example.com"}
	h.FireUserUpdated(context.Background(), logger, user)

	if capturedUser == nil {
		t.Fatal("hook should have been called")
	}
	if capturedUser.ID != "user-456" {
		t.Errorf("capturedUser.ID = %s, want user-456", capturedUser.ID)
	}
}

func TestHooks_FireSignIn_NilHook(t *testing.T) {
	h := &Hooks{}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	// Should not panic with nil hook
	h.FireSignIn(context.Background(), logger, &models.User{ID: "user-123"}, &models.Session{ID: "session-123"})
}

func TestHooks_FireSignIn_WithHook(t *testing.T) {
	var capturedUser *models.User
	var capturedSession *models.Session
	h := &Hooks{
		OnSignIn: func(ctx context.Context, user *models.User, session *models.Session) error {
			capturedUser = user
			capturedSession = session
			return nil
		},
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	user := &models.User{ID: "user-123"}
	session := &models.Session{ID: "session-123"}
	h.FireSignIn(context.Background(), logger, user, session)

	if capturedUser == nil || capturedSession == nil {
		t.Fatal("hook should have been called with user and session")
	}
	if capturedUser.ID != "user-123" {
		t.Errorf("capturedUser.ID = %s, want user-123", capturedUser.ID)
	}
	if capturedSession.ID != "session-123" {
		t.Errorf("capturedSession.ID = %s, want session-123", capturedSession.ID)
	}
}

func TestHooks_FireSignOut_NilHook(t *testing.T) {
	h := &Hooks{}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	// Should not panic with nil hook
	h.FireSignOut(context.Background(), logger, &models.User{ID: "user-123"}, &models.Session{ID: "session-123"})
}

func TestHooks_FireSignOut_WithHook(t *testing.T) {
	var capturedUser *models.User
	var capturedSession *models.Session
	h := &Hooks{
		OnSignOut: func(ctx context.Context, user *models.User, session *models.Session) error {
			capturedUser = user
			capturedSession = session
			return nil
		},
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	user := &models.User{ID: "user-123"}
	session := &models.Session{ID: "session-123"}
	h.FireSignOut(context.Background(), logger, user, session)

	if capturedUser == nil || capturedSession == nil {
		t.Fatal("hook should have been called")
	}
}

func TestHooks_FirePasswordChanged_NilHook(t *testing.T) {
	h := &Hooks{}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	// Should not panic with nil hook
	h.FirePasswordChanged(context.Background(), logger, &models.User{ID: "user-123"})
}

func TestHooks_FirePasswordChanged_WithHook(t *testing.T) {
	called := false
	h := &Hooks{
		OnPasswordChanged: func(ctx context.Context, user *models.User) error {
			called = true
			return nil
		},
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	h.FirePasswordChanged(context.Background(), logger, &models.User{ID: "user-123"})

	if !called {
		t.Error("hook should have been called")
	}
}

func TestHooks_FirePasswordResetRequested_NilHook(t *testing.T) {
	h := &Hooks{}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	// Should not panic with nil hook
	h.FirePasswordResetRequested(context.Background(), logger, &models.User{ID: "user-123"}, "reset-token")
}

func TestHooks_FirePasswordResetRequested_WithHook(t *testing.T) {
	var capturedToken string
	h := &Hooks{
		OnPasswordResetRequested: func(ctx context.Context, user *models.User, token string) error {
			capturedToken = token
			return nil
		},
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	h.FirePasswordResetRequested(context.Background(), logger, &models.User{ID: "user-123"}, "my-reset-token")

	if capturedToken != "my-reset-token" {
		t.Errorf("capturedToken = %s, want my-reset-token", capturedToken)
	}
}

func TestHooks_FireEmailVerified_NilHook(t *testing.T) {
	h := &Hooks{}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	// Should not panic with nil hook
	h.FireEmailVerified(context.Background(), logger, &models.User{ID: "user-123"})
}

func TestHooks_FireEmailVerified_WithHook(t *testing.T) {
	called := false
	h := &Hooks{
		OnEmailVerified: func(ctx context.Context, user *models.User) error {
			called = true
			return nil
		},
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	h.FireEmailVerified(context.Background(), logger, &models.User{ID: "user-123"})

	if !called {
		t.Error("hook should have been called")
	}
}

func TestHooks_FireEmailVerificationRequested_NilHook(t *testing.T) {
	h := &Hooks{}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	// Should not panic with nil hook
	h.FireEmailVerificationRequested(context.Background(), logger, &models.User{ID: "user-123"}, "verify-token")
}

func TestHooks_FireEmailVerificationRequested_WithHook(t *testing.T) {
	var capturedToken string
	h := &Hooks{
		OnEmailVerificationRequested: func(ctx context.Context, user *models.User, token string) error {
			capturedToken = token
			return nil
		},
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	h.FireEmailVerificationRequested(context.Background(), logger, &models.User{ID: "user-123"}, "my-verify-token")

	if capturedToken != "my-verify-token" {
		t.Errorf("capturedToken = %s, want my-verify-token", capturedToken)
	}
}

func TestHooks_FireOAuthAccountLinked_NilHook(t *testing.T) {
	h := &Hooks{}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	// Should not panic with nil hook
	h.FireOAuthAccountLinked(context.Background(), logger, &models.User{ID: "user-123"}, &models.Account{ID: "account-123"})
}

func TestHooks_FireOAuthAccountLinked_WithHook(t *testing.T) {
	var capturedUser *models.User
	var capturedAccount *models.Account
	h := &Hooks{
		OnOAuthAccountLinked: func(ctx context.Context, user *models.User, account *models.Account) error {
			capturedUser = user
			capturedAccount = account
			return nil
		},
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	user := &models.User{ID: "user-123"}
	account := &models.Account{ID: "account-123", Provider: "google"}
	h.FireOAuthAccountLinked(context.Background(), logger, user, account)

	if capturedUser == nil || capturedAccount == nil {
		t.Fatal("hook should have been called")
	}
	if capturedAccount.Provider != "google" {
		t.Errorf("capturedAccount.Provider = %s, want google", capturedAccount.Provider)
	}
}

func TestHooks_AllHooksNil(t *testing.T) {
	h := &Hooks{}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	ctx := context.Background()
	user := &models.User{ID: "user-123"}
	session := &models.Session{ID: "session-123"}
	account := &models.Account{ID: "account-123"}

	// None of these should panic
	h.FireUserCreated(ctx, logger, user)
	h.FireUserUpdated(ctx, logger, user)
	h.FireSignIn(ctx, logger, user, session)
	h.FireSignOut(ctx, logger, user, session)
	h.FirePasswordChanged(ctx, logger, user)
	h.FirePasswordResetRequested(ctx, logger, user, "token")
	h.FireEmailVerified(ctx, logger, user)
	h.FireEmailVerificationRequested(ctx, logger, user, "token")
	h.FireOAuthAccountLinked(ctx, logger, user, account)

	// No errors should be logged
	if buf.Len() > 0 {
		t.Errorf("no output expected for nil hooks, got: %s", buf.String())
	}
}

func TestHooks_AllHooksError(t *testing.T) {
	h := &Hooks{
		OnUserCreated: func(ctx context.Context, user *models.User) error {
			return errors.New("error1")
		},
		OnUserUpdated: func(ctx context.Context, user *models.User) error {
			return errors.New("error2")
		},
		OnSignIn: func(ctx context.Context, user *models.User, session *models.Session) error {
			return errors.New("error3")
		},
		OnSignOut: func(ctx context.Context, user *models.User, session *models.Session) error {
			return errors.New("error4")
		},
		OnPasswordChanged: func(ctx context.Context, user *models.User) error {
			return errors.New("error5")
		},
		OnPasswordResetRequested: func(ctx context.Context, user *models.User, token string) error {
			return errors.New("error6")
		},
		OnEmailVerified: func(ctx context.Context, user *models.User) error {
			return errors.New("error7")
		},
		OnEmailVerificationRequested: func(ctx context.Context, user *models.User, token string) error {
			return errors.New("error8")
		},
		OnOAuthAccountLinked: func(ctx context.Context, user *models.User, account *models.Account) error {
			return errors.New("error9")
		},
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	ctx := context.Background()
	user := &models.User{ID: "user-123"}
	session := &models.Session{ID: "session-123"}
	account := &models.Account{ID: "account-123"}

	// All hooks should be called and errors logged
	h.FireUserCreated(ctx, logger, user)
	h.FireUserUpdated(ctx, logger, user)
	h.FireSignIn(ctx, logger, user, session)
	h.FireSignOut(ctx, logger, user, session)
	h.FirePasswordChanged(ctx, logger, user)
	h.FirePasswordResetRequested(ctx, logger, user, "token")
	h.FireEmailVerified(ctx, logger, user)
	h.FireEmailVerificationRequested(ctx, logger, user, "token")
	h.FireOAuthAccountLinked(ctx, logger, user, account)

	output := buf.String()
	// All 9 errors should be logged
	if strings.Count(output, "hook failed") != 9 {
		t.Errorf("expected 9 'hook failed' entries, got %d", strings.Count(output, "hook failed"))
	}
}

func TestHooks_ContextPassed(t *testing.T) {
	type ctxKey string
	key := ctxKey("test-key")
	var capturedValue string

	h := &Hooks{
		OnUserCreated: func(ctx context.Context, user *models.User) error {
			if v, ok := ctx.Value(key).(string); ok {
				capturedValue = v
			}
			return nil
		},
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	ctx := context.WithValue(context.Background(), key, "test-value")
	h.FireUserCreated(ctx, logger, &models.User{ID: "user-123"})

	if capturedValue != "test-value" {
		t.Errorf("context value not passed to hook, got: %s", capturedValue)
	}
}

func TestHooks_EmptyStruct(t *testing.T) {
	h := Hooks{} // Not a pointer
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	// Should work with value receiver too
	h.FireUserCreated(context.Background(), logger, &models.User{ID: "user-123"})
}
