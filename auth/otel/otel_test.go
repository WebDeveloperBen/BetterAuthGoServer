package otel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestNew(t *testing.T) {
	inst, err := New()
	if err != nil {
		t.Fatalf("Failed to create instrumentation: %v", err)
	}

	if inst.Tracer() == nil {
		t.Error("Tracer should not be nil")
	}
	if inst.Meter() == nil {
		t.Error("Meter should not be nil")
	}
	if inst.Metrics() == nil {
		t.Error("Metrics should not be nil")
	}
}

func TestNewWithOptions(t *testing.T) {
	// Create test providers
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	mp := sdkmetric.NewMeterProvider()

	inst, err := New(
		WithServiceName("test-auth"),
		WithServiceVersion("1.0.0"),
		WithTracerProvider(tp),
		WithMeterProvider(mp),
	)
	if err != nil {
		t.Fatalf("Failed to create instrumentation: %v", err)
	}

	if inst.Tracer() == nil {
		t.Error("Tracer should not be nil")
	}
	if inst.Meter() == nil {
		t.Error("Meter should not be nil")
	}
}

func TestMiddleware(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	otel.SetTracerProvider(tp)

	inst, err := New(WithTracerProvider(tp))
	if err != nil {
		t.Fatalf("Failed to create instrumentation: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := inst.Middleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusOK)
	}

	// Check that a span was created
	spans := exporter.GetSpans()
	if len(spans) == 0 {
		t.Error("Expected at least one span to be created")
	}

	// Verify span attributes
	span := spans[0]
	if span.Name != "auth.request" {
		t.Errorf("Span name = %s, want auth.request", span.Name)
	}

	foundMethod := false
	foundPath := false
	for _, attr := range span.Attributes {
		if attr.Key == "http.method" && attr.Value.AsString() == "GET" {
			foundMethod = true
		}
		if attr.Key == "http.path" && attr.Value.AsString() == "/test" {
			foundPath = true
		}
	}
	if !foundMethod {
		t.Error("Missing http.method attribute")
	}
	if !foundPath {
		t.Error("Missing http.path attribute")
	}
}

func TestStartSpan(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))

	inst, err := New(WithTracerProvider(tp))
	if err != nil {
		t.Fatalf("Failed to create instrumentation: %v", err)
	}

	req := httptest.NewRequest("POST", "/auth/signup", nil)

	span, newReq := inst.StartSpan(req, "auth.test.operation",
		attribute.String("test.key", "test.value"),
	)
	defer span.End()

	if span == nil {
		t.Error("Span should not be nil")
	}
	if newReq == nil {
		t.Error("Request should not be nil")
	}
	if newReq.Context() == req.Context() {
		t.Error("Request context should be updated with span")
	}
}

func TestTraceSignUp(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))

	inst, err := New(WithTracerProvider(tp))
	if err != nil {
		t.Fatalf("Failed to create instrumentation: %v", err)
	}

	req := httptest.NewRequest("POST", "/auth/signup", nil)
	span, _ := inst.TraceSignUp(req, "user@example.com")
	span.End()

	spans := exporter.GetSpans()
	if len(spans) == 0 {
		t.Fatal("Expected a span to be created")
	}

	if spans[0].Name != "auth.signup" {
		t.Errorf("Span name = %s, want auth.signup", spans[0].Name)
	}
}

func TestTraceSignIn(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))

	inst, err := New(WithTracerProvider(tp))
	if err != nil {
		t.Fatalf("Failed to create instrumentation: %v", err)
	}

	req := httptest.NewRequest("POST", "/auth/signin", nil)
	span, _, startTime := inst.TraceSignIn(req, "user@example.com")
	span.End()

	if startTime.IsZero() {
		t.Error("Start time should not be zero")
	}

	spans := exporter.GetSpans()
	if len(spans) == 0 {
		t.Fatal("Expected a span to be created")
	}

	if spans[0].Name != "auth.signin" {
		t.Errorf("Span name = %s, want auth.signin", spans[0].Name)
	}
}

func TestTraceOAuth(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))

	inst, err := New(WithTracerProvider(tp))
	if err != nil {
		t.Fatalf("Failed to create instrumentation: %v", err)
	}

	req := httptest.NewRequest("GET", "/auth/oauth/google", nil)
	span, _ := inst.TraceOAuthBegin(req, "google")
	span.End()

	spans := exporter.GetSpans()
	if len(spans) == 0 {
		t.Fatal("Expected a span to be created")
	}

	if spans[0].Name != "auth.oauth.begin" {
		t.Errorf("Span name = %s, want auth.oauth.begin", spans[0].Name)
	}

	// Check for provider attribute
	foundProvider := false
	for _, attr := range spans[0].Attributes {
		if attr.Key == "auth.oauth.provider" && attr.Value.AsString() == "google" {
			foundProvider = true
		}
	}
	if !foundProvider {
		t.Error("Missing auth.oauth.provider attribute")
	}
}

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		email  string
		domain string
	}{
		{"user@example.com", "example.com"},
		{"test@gmail.com", "gmail.com"},
		{"invalid", "unknown"},
		{"@domain.com", "domain.com"},
	}

	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			got := extractDomain(tt.email)
			if got != tt.domain {
				t.Errorf("extractDomain(%s) = %s, want %s", tt.email, got, tt.domain)
			}
		})
	}
}

func TestMetrics_RecordSignUp(t *testing.T) {
	mp := sdkmetric.NewMeterProvider()
	inst, err := New(WithMeterProvider(mp))
	if err != nil {
		t.Fatalf("Failed to create instrumentation: %v", err)
	}

	ctx := context.Background()

	// These should not panic
	inst.Metrics().RecordSignUp(ctx, true)
	inst.Metrics().RecordSignUp(ctx, false)
}

func TestMetrics_RecordSignIn(t *testing.T) {
	mp := sdkmetric.NewMeterProvider()
	inst, err := New(WithMeterProvider(mp))
	if err != nil {
		t.Fatalf("Failed to create instrumentation: %v", err)
	}

	ctx := context.Background()

	// These should not panic
	inst.Metrics().RecordSignIn(ctx, true, 100.5)
	inst.Metrics().RecordSignIn(ctx, false, 50.0)
}

func TestMetrics_RecordSession(t *testing.T) {
	mp := sdkmetric.NewMeterProvider()
	inst, err := New(WithMeterProvider(mp))
	if err != nil {
		t.Fatalf("Failed to create instrumentation: %v", err)
	}

	ctx := context.Background()

	// These should not panic
	inst.Metrics().RecordSessionCreated(ctx)
	inst.Metrics().RecordSessionDestroyed(ctx)
}

func TestMetrics_RecordOAuth(t *testing.T) {
	mp := sdkmetric.NewMeterProvider()
	inst, err := New(WithMeterProvider(mp))
	if err != nil {
		t.Fatalf("Failed to create instrumentation: %v", err)
	}

	ctx := context.Background()

	// These should not panic
	inst.Metrics().RecordOAuthAttempt(ctx, "google", true)
	inst.Metrics().RecordOAuthAttempt(ctx, "github", false)
}

func TestMetrics_RecordTokenOperation(t *testing.T) {
	mp := sdkmetric.NewMeterProvider()
	inst, err := New(WithMeterProvider(mp))
	if err != nil {
		t.Fatalf("Failed to create instrumentation: %v", err)
	}

	ctx := context.Background()

	// These should not panic
	inst.Metrics().RecordTokenOperation(ctx, "issue", true)
	inst.Metrics().RecordTokenOperation(ctx, "refresh", true)
	inst.Metrics().RecordTokenOperation(ctx, "revoke", false)
}

func TestMetrics_RecordRateLimit(t *testing.T) {
	mp := sdkmetric.NewMeterProvider()
	inst, err := New(WithMeterProvider(mp))
	if err != nil {
		t.Fatalf("Failed to create instrumentation: %v", err)
	}

	ctx := context.Background()

	// This should not panic
	inst.Metrics().RecordRateLimitExceeded(ctx, "/sign-in")
}

func TestMetrics_RecordAdmin(t *testing.T) {
	mp := sdkmetric.NewMeterProvider()
	inst, err := New(WithMeterProvider(mp))
	if err != nil {
		t.Fatalf("Failed to create instrumentation: %v", err)
	}

	ctx := context.Background()

	// These should not panic
	inst.Metrics().RecordAdminOperation(ctx, "ban", true)
	inst.Metrics().RecordAdminOperation(ctx, "unban", true)
	inst.Metrics().RecordAdminOperation(ctx, "set_role", false)
}

func TestMetrics_RecordError(t *testing.T) {
	mp := sdkmetric.NewMeterProvider()
	inst, err := New(WithMeterProvider(mp))
	if err != nil {
		t.Fatalf("Failed to create instrumentation: %v", err)
	}

	ctx := context.Background()

	// This should not panic
	inst.Metrics().RecordAuthError(ctx, "invalid_credentials")
}

func TestRecordError(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))

	inst, err := New(WithTracerProvider(tp))
	if err != nil {
		t.Fatalf("Failed to create instrumentation: %v", err)
	}

	req := httptest.NewRequest("POST", "/test", nil)
	span, _ := inst.StartSpan(req, "test.operation")

	// Should not panic with nil
	RecordError(nil, nil)

	// Should record error
	testErr := http.ErrBodyNotAllowed
	RecordError(span, testErr)
	span.End()

	spans := exporter.GetSpans()
	if len(spans) == 0 {
		t.Fatal("Expected a span")
	}

	// Check that error was recorded
	if len(spans[0].Events) == 0 {
		t.Error("Expected error event to be recorded")
	}
}

func TestRecordSuccess(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))

	inst, err := New(WithTracerProvider(tp))
	if err != nil {
		t.Fatalf("Failed to create instrumentation: %v", err)
	}

	req := httptest.NewRequest("POST", "/test", nil)
	span, _ := inst.StartSpan(req, "test.operation")

	// Should not panic with nil
	RecordSuccess(nil)

	RecordSuccess(span)
	span.End()
}

func TestSetUserID(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))

	inst, err := New(WithTracerProvider(tp))
	if err != nil {
		t.Fatalf("Failed to create instrumentation: %v", err)
	}

	req := httptest.NewRequest("POST", "/test", nil)
	span, _ := inst.StartSpan(req, "test.operation")

	// Should not panic with nil
	SetUserID(nil, "user-123")

	SetUserID(span, "user-123")
	span.End()

	spans := exporter.GetSpans()
	if len(spans) == 0 {
		t.Fatal("Expected a span")
	}

	// Check for user_id attribute
	foundUserID := false
	for _, attr := range spans[0].Attributes {
		if attr.Key == "auth.user_id" && attr.Value.AsString() == "user-123" {
			foundUserID = true
		}
	}
	if !foundUserID {
		t.Error("Missing auth.user_id attribute")
	}
}

func TestMiddlewareErrorStatus(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))

	inst, err := New(WithTracerProvider(tp))
	if err != nil {
		t.Fatalf("Failed to create instrumentation: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	wrapped := inst.Middleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	spans := exporter.GetSpans()
	if len(spans) == 0 {
		t.Fatal("Expected a span")
	}

	// Check for status code attribute
	foundStatus := false
	for _, attr := range spans[0].Attributes {
		if attr.Key == "http.status_code" && attr.Value.AsInt64() == 401 {
			foundStatus = true
		}
	}
	if !foundStatus {
		t.Error("Missing http.status_code attribute")
	}
}

func TestResponseWriter(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: rec, statusCode: http.StatusOK}

	// Test default status
	if rw.statusCode != http.StatusOK {
		t.Errorf("Default status = %d, want %d", rw.statusCode, http.StatusOK)
	}

	// Test WriteHeader
	rw.WriteHeader(http.StatusCreated)
	if rw.statusCode != http.StatusCreated {
		t.Errorf("Status after WriteHeader = %d, want %d", rw.statusCode, http.StatusCreated)
	}
}

func BenchmarkMiddleware(b *testing.B) {
	inst, _ := New()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := inst.Middleware(handler)
	req := httptest.NewRequest("GET", "/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)
	}
}

func BenchmarkMetricsRecording(b *testing.B) {
	inst, _ := New()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		inst.Metrics().RecordSignIn(ctx, true, float64(time.Millisecond*100))
	}
}
