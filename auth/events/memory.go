// Package events provides an event bus for publishing and subscribing to authentication events.
package events

import (
	"context"
	"sync"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
)

// InMemoryPubSub is an in-memory implementation of the PubSub interface.
// It is suitable for single-instance deployments and testing.
type InMemoryPubSub struct {
	mu          sync.RWMutex
	subscribers map[string][]chan *models.Message
	closed      bool
	closedChans []chan *models.Message
}

// NewInMemoryPubSub creates a new in-memory PubSub implementation.
func NewInMemoryPubSub() models.PubSub {
	return &InMemoryPubSub{
		subscribers: make(map[string][]chan *models.Message),
		closedChans: make([]chan *models.Message, 0),
	}
}

// Publish sends a message to all subscribers of the specified topic.
func (s *InMemoryPubSub) Publish(ctx context.Context, topic string, msg *models.Message) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil
	}

	subscribers, exists := s.subscribers[topic]
	if !exists {
		return nil
	}

	for _, ch := range subscribers {
		select {
		case ch <- msg:
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Channel full, skip (non-blocking)
		}
	}

	return nil
}

// Subscribe returns a channel that receives messages from the specified topic.
func (s *InMemoryPubSub) Subscribe(ctx context.Context, topic string) (<-chan *models.Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		ch := make(chan *models.Message)
		close(ch)
		return ch, nil
	}

	// Create buffered channel for this subscriber
	ch := make(chan *models.Message, 100)

	s.subscribers[topic] = append(s.subscribers[topic], ch)
	s.closedChans = append(s.closedChans, ch)

	return ch, nil
}

// Close closes the pub/sub and all subscriber channels.
func (s *InMemoryPubSub) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true

	for _, ch := range s.closedChans {
		close(ch)
	}

	s.subscribers = nil
	s.closedChans = nil

	return nil
}
