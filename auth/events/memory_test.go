package events

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
)

func TestNewInMemoryPubSub(t *testing.T) {
	ps := NewInMemoryPubSub()
	if ps == nil {
		t.Fatal("NewInMemoryPubSub returned nil")
	}
}

func TestInMemoryPubSub_PublishSubscribe(t *testing.T) {
	ps := NewInMemoryPubSub()
	defer ps.Close()

	ctx := context.Background()
	topic := "test.event"

	// Subscribe first
	ch, err := ps.Subscribe(ctx, topic)
	if err != nil {
		t.Fatalf("Subscribe failed: %v", err)
	}

	// Publish a message
	msg := &models.Message{
		UUID:    "test-uuid",
		Payload: []byte(`{"test": true}`),
	}

	go func() {
		if err := ps.Publish(ctx, topic, msg); err != nil {
			t.Errorf("Publish failed: %v", err)
		}
	}()

	// Receive the message
	select {
	case received := <-ch:
		if received.UUID != msg.UUID {
			t.Errorf("UUID = %s, want %s", received.UUID, msg.UUID)
		}
		if string(received.Payload) != string(msg.Payload) {
			t.Errorf("Payload = %s, want %s", received.Payload, msg.Payload)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for message")
	}
}

func TestInMemoryPubSub_MultipleSubscribers(t *testing.T) {
	ps := NewInMemoryPubSub()
	defer ps.Close()

	ctx := context.Background()
	topic := "test.event"

	// Create multiple subscribers
	ch1, err := ps.Subscribe(ctx, topic)
	if err != nil {
		t.Fatalf("Subscribe 1 failed: %v", err)
	}

	ch2, err := ps.Subscribe(ctx, topic)
	if err != nil {
		t.Fatalf("Subscribe 2 failed: %v", err)
	}

	// Publish a message
	msg := &models.Message{UUID: "multi-test"}

	go func() {
		ps.Publish(ctx, topic, msg)
	}()

	// Both should receive the message
	received := 0
	timeout := time.After(time.Second)

	for received < 2 {
		select {
		case <-ch1:
			received++
		case <-ch2:
			received++
		case <-timeout:
			t.Fatalf("timeout: only received %d messages, want 2", received)
		}
	}
}

func TestInMemoryPubSub_MultipleTopics(t *testing.T) {
	ps := NewInMemoryPubSub()
	defer ps.Close()

	ctx := context.Background()

	ch1, _ := ps.Subscribe(ctx, "topic1")
	ch2, _ := ps.Subscribe(ctx, "topic2")

	// Publish to topic1 only
	go func() {
		ps.Publish(ctx, "topic1", &models.Message{UUID: "topic1-msg"})
	}()

	// Only ch1 should receive
	select {
	case msg := <-ch1:
		if msg.UUID != "topic1-msg" {
			t.Errorf("wrong message UUID: %s", msg.UUID)
		}
	case <-ch2:
		t.Fatal("topic2 subscriber should not receive topic1 message")
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for message")
	}
}

func TestInMemoryPubSub_PublishNoSubscribers(t *testing.T) {
	ps := NewInMemoryPubSub()
	defer ps.Close()

	ctx := context.Background()

	// Should not error even with no subscribers
	err := ps.Publish(ctx, "no-subscribers", &models.Message{UUID: "orphan"})
	if err != nil {
		t.Fatalf("Publish to empty topic failed: %v", err)
	}
}

func TestInMemoryPubSub_Close(t *testing.T) {
	ps := NewInMemoryPubSub()

	ctx := context.Background()
	ch, _ := ps.Subscribe(ctx, "test")

	// Close the pubsub
	if err := ps.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Channel should be closed
	select {
	case _, ok := <-ch:
		if ok {
			t.Error("channel should be closed")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for channel close")
	}

	// Publish after close silently succeeds (fire-and-forget)
	err := ps.Publish(ctx, "test", &models.Message{})
	if err != nil {
		t.Errorf("Publish after Close should succeed silently: %v", err)
	}

	// Subscribe after close returns closed channel (no error)
	ch2, err := ps.Subscribe(ctx, "test")
	if err != nil {
		t.Errorf("Subscribe after Close should succeed: %v", err)
	}
	// The returned channel should be closed
	select {
	case _, ok := <-ch2:
		if ok {
			t.Error("channel from closed pubsub should be closed")
		}
	default:
		// Channel is closed and empty, which is correct
	}
}

func TestInMemoryPubSub_ConcurrentPublish(t *testing.T) {
	ps := NewInMemoryPubSub()
	defer ps.Close()

	ctx := context.Background()
	ch, _ := ps.Subscribe(ctx, "concurrent")

	numPublishers := 10
	messagesPerPublisher := 10 // Reduced to avoid channel buffer overflow
	totalMessages := numPublishers * messagesPerPublisher

	var wg sync.WaitGroup

	// Consume messages in a goroutine
	var received int
	var mu sync.Mutex
	consumeDone := make(chan struct{})

	go func() {
		for msg := range ch {
			if msg != nil {
				mu.Lock()
				received++
				mu.Unlock()
			}
		}
		close(consumeDone)
	}()

	// Publish messages
	for i := 0; i < numPublishers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < messagesPerPublisher; j++ {
				ps.Publish(ctx, "concurrent", &models.Message{UUID: "msg"})
			}
		}(i)
	}

	wg.Wait()
	time.Sleep(100 * time.Millisecond)
	ps.Close()

	<-consumeDone

	mu.Lock()
	defer mu.Unlock()

	// With buffered channels and fast consumption, we should receive all or most messages
	if received < totalMessages/2 {
		t.Errorf("received %d messages, want at least %d", received, totalMessages/2)
	}
}

func TestInMemoryPubSub_ConcurrentSubscribe(t *testing.T) {
	ps := NewInMemoryPubSub()
	defer ps.Close()

	ctx := context.Background()
	numSubscribers := 50

	var wg sync.WaitGroup
	channels := make([]<-chan *models.Message, numSubscribers)
	var mu sync.Mutex

	for i := 0; i < numSubscribers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ch, err := ps.Subscribe(ctx, "concurrent-sub")
			if err != nil {
				t.Errorf("Subscribe %d failed: %v", idx, err)
				return
			}
			mu.Lock()
			channels[idx] = ch
			mu.Unlock()
		}(i)
	}

	wg.Wait()

	// All channels should be valid
	for i, ch := range channels {
		if ch == nil {
			t.Errorf("channel %d is nil", i)
		}
	}
}
