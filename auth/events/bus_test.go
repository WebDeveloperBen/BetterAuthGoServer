package events

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
)

func TestNew(t *testing.T) {
	bus := New(Config{
		PubSub: NewInMemoryPubSub(),
		Logger: slog.Default(),
	})
	defer func() { _ = bus.Close() }()

	if bus == nil {
		t.Fatal("New returned nil")
	}
}

func TestDefault(t *testing.T) {
	bus := Default(slog.Default())
	defer func() { _ = bus.Close() }()

	if bus == nil {
		t.Fatal("Default returned nil")
	}
}

func TestEventBus_PublishSubscribe(t *testing.T) {
	bus := Default(slog.Default())
	defer func() { _ = bus.Close() }()

	ctx := context.Background()
	called := make(chan struct{})

	_, err := bus.Subscribe(models.EventUserCreated, func(ctx context.Context, e models.Event) error {
		close(called)
		return nil
	})
	if err != nil {
		t.Fatalf("Subscribe failed: %v", err)
	}

	// Wait for subscription to be ready
	time.Sleep(50 * time.Millisecond)

	payload, _ := json.Marshal(models.UserCreatedPayload{User: &models.User{ID: "test-123"}})
	event := models.Event{
		Type:    models.EventUserCreated,
		Payload: payload,
	}

	if err := bus.Publish(ctx, event); err != nil {
		t.Fatalf("Publish failed: %v", err)
	}

	select {
	case <-called:
		// Success
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for handler")
	}
}

func TestEventBus_MultipleHandlers(t *testing.T) {
	bus := Default(slog.Default())
	defer func() { _ = bus.Close() }()

	var count atomic.Int32
	done := make(chan struct{})

	// Add 3 handlers for the same event
	for i := 0; i < 3; i++ {
		_, _ = bus.Subscribe(models.EventSignedIn, func(ctx context.Context, e models.Event) error {
			if count.Add(1) == 3 {
				close(done)
			}
			return nil
		})
	}

	// Wait for subscriptions
	time.Sleep(50 * time.Millisecond)

	payload, _ := json.Marshal(models.SignedInPayload{})
	_ = bus.Publish(context.Background(), models.Event{
		Type:    models.EventSignedIn,
		Payload: payload,
	})

	select {
	case <-done:
		if count.Load() != 3 {
			t.Errorf("count = %d, want 3", count.Load())
		}
	case <-time.After(time.Second):
		t.Fatalf("timeout: only %d handlers called", count.Load())
	}
}

func TestEventBus_Unsubscribe(t *testing.T) {
	bus := Default(slog.Default())
	defer func() { _ = bus.Close() }()

	var count atomic.Int32

	id, _ := bus.Subscribe(models.EventSignedOut, func(ctx context.Context, e models.Event) error {
		count.Add(1)
		return nil
	})

	// Wait for subscription
	time.Sleep(50 * time.Millisecond)

	// Publish first event
	payload, _ := json.Marshal(models.SignedOutPayload{})
	_ = bus.Publish(context.Background(), models.Event{
		Type:    models.EventSignedOut,
		Payload: payload,
	})

	// Wait for handler
	time.Sleep(100 * time.Millisecond)

	if count.Load() != 1 {
		t.Fatalf("first publish: count = %d, want 1", count.Load())
	}

	// Unsubscribe
	bus.Unsubscribe(models.EventSignedOut, id)

	// Wait for unsubscribe to take effect
	time.Sleep(50 * time.Millisecond)

	// Publish second event - should not be handled
	_ = bus.Publish(context.Background(), models.Event{
		Type:    models.EventSignedOut,
		Payload: payload,
	})

	time.Sleep(100 * time.Millisecond)

	if count.Load() != 1 {
		t.Errorf("after unsubscribe: count = %d, want 1", count.Load())
	}
}

func TestEventBus_HandlerError(t *testing.T) {
	bus := Default(slog.Default())
	defer func() { _ = bus.Close() }()

	errHandler := errors.New("handler error")
	var called atomic.Bool

	_, _ = bus.Subscribe(models.EventPasswordChanged, func(ctx context.Context, e models.Event) error {
		called.Store(true)
		return errHandler
	})

	time.Sleep(50 * time.Millisecond)

	payload, _ := json.Marshal(models.PasswordChangedPayload{})
	err := bus.Publish(context.Background(), models.Event{
		Type:    models.EventPasswordChanged,
		Payload: payload,
	})

	// Publish should succeed even if handler fails
	if err != nil {
		t.Errorf("Publish should not fail: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	if !called.Load() {
		t.Error("handler should have been called")
	}
}

func TestEventBus_ConcurrentPublish(t *testing.T) {
	bus := Default(slog.Default())
	defer func() { _ = bus.Close() }()

	var count atomic.Int32
	numPublishes := 100

	_, _ = bus.Subscribe(models.EventEmailVerified, func(ctx context.Context, e models.Event) error {
		count.Add(1)
		return nil
	})

	time.Sleep(50 * time.Millisecond)

	var wg sync.WaitGroup
	for i := 0; i < numPublishes; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload, _ := json.Marshal(models.EmailVerifiedPayload{})
			_ = bus.Publish(context.Background(), models.Event{
				Type:    models.EventEmailVerified,
				Payload: payload,
			})
		}()
	}

	wg.Wait()
	time.Sleep(500 * time.Millisecond) // Wait for all handlers

	if count.Load() != int32(numPublishes) {
		t.Errorf("count = %d, want %d", count.Load(), numPublishes)
	}
}

func TestEventBus_DifferentEventTypes(t *testing.T) {
	bus := Default(slog.Default())
	defer func() { _ = bus.Close() }()

	userCreatedCalled := make(chan struct{})
	signedInCalled := make(chan struct{})

	_, _ = bus.Subscribe(models.EventUserCreated, func(ctx context.Context, e models.Event) error {
		close(userCreatedCalled)
		return nil
	})

	_, _ = bus.Subscribe(models.EventSignedIn, func(ctx context.Context, e models.Event) error {
		close(signedInCalled)
		return nil
	})

	time.Sleep(50 * time.Millisecond)

	// Publish EventUserCreated
	payload1, _ := json.Marshal(models.UserCreatedPayload{})
	_ = bus.Publish(context.Background(), models.Event{
		Type:    models.EventUserCreated,
		Payload: payload1,
	})

	select {
	case <-userCreatedCalled:
		// Expected
	case <-time.After(time.Second):
		t.Fatal("EventUserCreated handler not called")
	}

	// SignedIn should not have been called yet
	select {
	case <-signedInCalled:
		t.Fatal("EventSignedIn should not be called")
	default:
		// Expected
	}

	// Now publish EventSignedIn
	payload2, _ := json.Marshal(models.SignedInPayload{})
	_ = bus.Publish(context.Background(), models.Event{
		Type:    models.EventSignedIn,
		Payload: payload2,
	})

	select {
	case <-signedInCalled:
		// Expected
	case <-time.After(time.Second):
		t.Fatal("EventSignedIn handler not called")
	}
}

func TestEventBus_Close(t *testing.T) {
	bus := Default(slog.Default())

	_, _ = bus.Subscribe(models.EventUserCreated, func(ctx context.Context, e models.Event) error {
		return nil
	})

	time.Sleep(50 * time.Millisecond)

	err := bus.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Close is idempotent
	err = bus.Close()
	if err != nil {
		t.Errorf("Second Close should succeed: %v", err)
	}
}

func TestEventBus_PayloadUnmarshal(t *testing.T) {
	bus := Default(slog.Default())
	defer func() { _ = bus.Close() }()

	done := make(chan struct{})
	var receivedUser *models.User

	_, _ = bus.Subscribe(models.EventUserCreated, func(ctx context.Context, e models.Event) error {
		var payload models.UserCreatedPayload
		if err := e.UnmarshalPayload(&payload); err != nil {
			t.Errorf("UnmarshalPayload failed: %v", err)
			return err
		}
		receivedUser = payload.User
		close(done)
		return nil
	})

	time.Sleep(50 * time.Millisecond)

	user := &models.User{
		ID:    "user-123",
		Email: "test@example.com",
		Name:  "Test User",
	}
	payload, _ := json.Marshal(models.UserCreatedPayload{User: user})
	_ = bus.Publish(context.Background(), models.Event{
		Type:    models.EventUserCreated,
		Payload: payload,
	})

	select {
	case <-done:
		if receivedUser == nil {
			t.Fatal("receivedUser is nil")
		}
		if receivedUser.ID != user.ID {
			t.Errorf("ID = %s, want %s", receivedUser.ID, user.ID)
		}
		if receivedUser.Email != user.Email {
			t.Errorf("Email = %s, want %s", receivedUser.Email, user.Email)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for handler")
	}
}

func TestEventBus_HandlerPanicRecovery(t *testing.T) {
	bus := Default(slog.Default())
	defer func() { _ = bus.Close() }()

	var count atomic.Int32

	// First handler panics
	_, _ = bus.Subscribe(models.EventPasswordResetRequested, func(ctx context.Context, e models.Event) error {
		count.Add(1)
		panic("test panic")
	})

	// Second handler should still be called
	_, _ = bus.Subscribe(models.EventPasswordResetRequested, func(ctx context.Context, e models.Event) error {
		count.Add(1)
		return nil
	})

	time.Sleep(50 * time.Millisecond)

	payload, _ := json.Marshal(models.PasswordResetRequestedPayload{})
	err := bus.Publish(context.Background(), models.Event{
		Type:    models.EventPasswordResetRequested,
		Payload: payload,
	})

	if err != nil {
		t.Errorf("Publish should not fail: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	// Both handlers should have been called (panic is recovered)
	if count.Load() != 2 {
		t.Errorf("count = %d, want 2 (both handlers should run despite panic)", count.Load())
	}
}

func TestEventBus_ConcurrencyLimit(t *testing.T) {
	bus := New(Config{
		PubSub:                NewInMemoryPubSub(),
		Logger:                slog.Default(),
		MaxConcurrentHandlers: 2, // Only 2 concurrent handlers
	})
	defer func() { _ = bus.Close() }()

	var concurrent atomic.Int32
	var maxConcurrent atomic.Int32

	_, _ = bus.Subscribe("test.event", func(ctx context.Context, e models.Event) error {
		current := concurrent.Add(1)
		defer concurrent.Add(-1)

		// Track max concurrency
		for {
			max := maxConcurrent.Load()
			if current <= max {
				break
			}
			if maxConcurrent.CompareAndSwap(max, current) {
				break
			}
		}

		time.Sleep(50 * time.Millisecond)
		return nil
	})

	time.Sleep(50 * time.Millisecond)

	// Publish many events
	for i := 0; i < 10; i++ {
		_ = bus.Publish(context.Background(), models.Event{
			Type:    "test.event",
			Payload: []byte(`{}`),
		})
	}

	time.Sleep(500 * time.Millisecond)

	// Max concurrent should be limited to 2
	if maxConcurrent.Load() > 2 {
		t.Errorf("max concurrent = %d, want <= 2", maxConcurrent.Load())
	}
}
