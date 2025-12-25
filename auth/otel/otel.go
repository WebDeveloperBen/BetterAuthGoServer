// Package otel provides OpenTelemetry instrumentation for the auth package.
// It includes tracing and metrics for authentication operations.
package otel

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

const (
	// InstrumentationName is the name used for OpenTelemetry instrumentation
	InstrumentationName = "github.com/webdeveloperben/BetterAuthGoServer/auth"
	// InstrumentationVersion is the version of this instrumentation
	InstrumentationVersion = "1.0.0"
)

// Instrumentation holds the OpenTelemetry tracer and meter for auth operations
type Instrumentation struct {
	tracer  trace.Tracer
	meter   metric.Meter
	metrics *Metrics
}

// Config holds configuration for OpenTelemetry instrumentation
type Config struct {
	// ServiceName is the name of the service for tracing
	ServiceName string
	// ServiceVersion is the version of the service
	ServiceVersion string
	// TracerProvider is an optional custom tracer provider
	TracerProvider trace.TracerProvider
	// MeterProvider is an optional custom meter provider
	MeterProvider metric.MeterProvider
}

// Option is a function that configures the instrumentation
type Option func(*Config)

// WithServiceName sets the service name for tracing
func WithServiceName(name string) Option {
	return func(c *Config) {
		c.ServiceName = name
	}
}

// WithServiceVersion sets the service version
func WithServiceVersion(version string) Option {
	return func(c *Config) {
		c.ServiceVersion = version
	}
}

// WithTracerProvider sets a custom tracer provider
func WithTracerProvider(tp trace.TracerProvider) Option {
	return func(c *Config) {
		c.TracerProvider = tp
	}
}

// WithMeterProvider sets a custom meter provider
func WithMeterProvider(mp metric.MeterProvider) Option {
	return func(c *Config) {
		c.MeterProvider = mp
	}
}

// New creates a new OpenTelemetry instrumentation instance
func New(opts ...Option) (*Instrumentation, error) {
	cfg := &Config{
		ServiceName:    "auth-service",
		ServiceVersion: InstrumentationVersion,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	// Use global providers if not specified
	tp := cfg.TracerProvider
	if tp == nil {
		tp = otel.GetTracerProvider()
	}

	mp := cfg.MeterProvider
	if mp == nil {
		mp = otel.GetMeterProvider()
	}

	tracer := tp.Tracer(
		InstrumentationName,
		trace.WithInstrumentationVersion(cfg.ServiceVersion),
	)

	meter := mp.Meter(
		InstrumentationName,
		metric.WithInstrumentationVersion(cfg.ServiceVersion),
	)

	metrics, err := NewMetrics(meter)
	if err != nil {
		return nil, err
	}

	return &Instrumentation{
		tracer:  tracer,
		meter:   meter,
		metrics: metrics,
	}, nil
}

// Tracer returns the OpenTelemetry tracer
func (i *Instrumentation) Tracer() trace.Tracer {
	return i.tracer
}

// Meter returns the OpenTelemetry meter
func (i *Instrumentation) Meter() metric.Meter {
	return i.meter
}

// Metrics returns the auth metrics
func (i *Instrumentation) Metrics() *Metrics {
	return i.metrics
}
