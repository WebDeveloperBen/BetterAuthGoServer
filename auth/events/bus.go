package events

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
)

// Config holds configuration for the EventBus
type Config struct {
	// MaxConcurrentHandlers limits the number of handlers that can run concurrently
	MaxConcurrentHandlers int

	// TopicPrefix is prepended to all event types when publishing
	TopicPrefix string

	// Logger for event bus operations
	Logger *slog.Logger

	// PubSub backend (defaults to in-memory if nil)
	PubSub models.PubSub
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() Config {
	return Config{
		MaxConcurrentHandlers: 100,
		TopicPrefix:           "auth",
		Logger:                slog.Default(),
		PubSub:                nil, // Will use in-memory
	}
}

type handlerEntry struct {
	id      models.SubscriptionID
	handler models.EventHandler
}

type topicState struct {
	handlers []handlerEntry
	cancel   context.CancelFunc
}

type eventBus struct {
	config Config
	pubsub models.PubSub
	logger *slog.Logger

	mu     sync.RWMutex
	topics map[string]*topicState

	subIDCounter atomic.Uint64

	// concurrency control
	handlerSem chan struct{}

	// lifecycle
	rootCtx context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// New creates a new EventBus with the given configuration.
func New(cfg Config) models.EventBus {
	if cfg.MaxConcurrentHandlers <= 0 {
		cfg.MaxConcurrentHandlers = 100
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.PubSub == nil {
		cfg.PubSub = NewInMemoryPubSub()
	}

	rootCtx, cancel := context.WithCancel(context.Background())

	return &eventBus{
		config:     cfg,
		pubsub:     cfg.PubSub,
		logger:     cfg.Logger,
		topics:     make(map[string]*topicState),
		handlerSem: make(chan struct{}, cfg.MaxConcurrentHandlers),
		rootCtx:    rootCtx,
		cancel:     cancel,
	}
}

// Default creates an EventBus with default configuration and the provided logger.
func Default(logger *slog.Logger) models.EventBus {
	cfg := DefaultConfig()
	cfg.Logger = logger
	return New(cfg)
}

// topic returns the full topic name with prefix
func (bus *eventBus) topic(eventType string) string {
	if bus.config.TopicPrefix == "" {
		return eventType
	}
	return bus.config.TopicPrefix + "." + eventType
}

// Publish sends an event to all subscribers.
func (bus *eventBus) Publish(ctx context.Context, evt models.Event) error {
	event := evt

	if event.Type == "" {
		return fmt.Errorf("eventbus: event type must not be empty")
	}
	if event.ID == "" {
		event.ID = uuid.NewString()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.Metadata == nil {
		event.Metadata = make(map[string]string)
	}

	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("eventbus: failed to marshal event: %w", err)
	}

	msg := &models.Message{
		UUID:    event.ID,
		Payload: payload,
		Metadata: map[string]string{
			"event_type": event.Type,
			"timestamp":  event.Timestamp.Format(time.RFC3339Nano),
		},
	}

	return bus.pubsub.Publish(ctx, bus.topic(event.Type), msg)
}

// Subscribe registers a handler for a specific event type.
func (bus *eventBus) Subscribe(
	eventType string,
	handler models.EventHandler,
) (models.SubscriptionID, error) {
	if handler == nil {
		return 0, fmt.Errorf("eventbus: handler must not be nil")
	}

	topic := bus.topic(eventType)
	id := models.SubscriptionID(bus.subIDCounter.Add(1))

	bus.mu.Lock()
	defer bus.mu.Unlock()

	state, exists := bus.topics[topic]

	// First subscriber → start consumer
	if !exists {
		ctx, cancel := context.WithCancel(bus.rootCtx)

		msgs, err := bus.pubsub.Subscribe(ctx, topic)
		if err != nil {
			cancel()
			return 0, fmt.Errorf("eventbus: failed to subscribe to topic %s: %w", topic, err)
		}

		state = &topicState{
			cancel: cancel,
		}
		bus.topics[topic] = state

		bus.wg.Add(1)
		go bus.consumeAndMultiplex(ctx, topic, msgs)
	}

	state.handlers = append(state.handlers, handlerEntry{
		id:      id,
		handler: handler,
	})

	return id, nil
}

// Unsubscribe removes a handler subscription.
func (bus *eventBus) Unsubscribe(eventType string, id models.SubscriptionID) {
	topic := bus.topic(eventType)

	bus.mu.Lock()
	defer bus.mu.Unlock()

	state, ok := bus.topics[topic]
	if !ok {
		return
	}

	handlers := state.handlers
	for i, entry := range handlers {
		if entry.id == id {
			state.handlers = append(handlers[:i], handlers[i+1:]...)
			break
		}
	}

	// No handlers left → stop consumer
	if len(state.handlers) == 0 {
		state.cancel()
		delete(bus.topics, topic)
	}
}

// consumeAndMultiplex receives messages from PubSub and dispatches to handlers.
func (bus *eventBus) consumeAndMultiplex(
	ctx context.Context,
	topic string,
	msgs <-chan *models.Message,
) {
	defer bus.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return

		case msg, ok := <-msgs:
			if !ok {
				return
			}

			var event models.Event
			if err := json.Unmarshal(msg.Payload, &event); err != nil {
				bus.logger.Error(
					"failed to unmarshal event",
					"error", err,
					"topic", topic,
					"message_id", msg.UUID,
				)
				continue
			}

			bus.mu.RLock()
			state := bus.topics[topic]
			if state == nil {
				bus.mu.RUnlock()
				continue
			}
			handlers := append([]handlerEntry(nil), state.handlers...)
			bus.mu.RUnlock()

			for _, entry := range handlers {
				bus.handlerSem <- struct{}{}
				bus.wg.Add(1)

				go bus.callHandler(ctx, entry.handler, event)
			}
		}
	}
}

// callHandler invokes a handler with panic recovery.
func (bus *eventBus) callHandler(
	ctx context.Context,
	handler models.EventHandler,
	event models.Event,
) {
	defer func() {
		if r := recover(); r != nil {
			bus.logger.Error(
				"event handler panicked",
				"panic", r,
				"event_type", event.Type,
				"event_id", event.ID,
			)
		}
		<-bus.handlerSem
		bus.wg.Done()
	}()

	if err := handler(ctx, event); err != nil {
		bus.logger.Error(
			"event handler error",
			"error", err,
			"event_type", event.Type,
			"event_id", event.ID,
		)
	}
}

// Close shuts down the event bus and waits for handlers to complete.
func (bus *eventBus) Close() error {
	// Stop everything
	bus.cancel()

	// Wait for consumers + handlers
	bus.wg.Wait()

	return bus.pubsub.Close()
}
