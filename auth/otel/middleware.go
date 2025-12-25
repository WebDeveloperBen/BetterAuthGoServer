package otel

import (
	"net/http"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Middleware returns HTTP middleware that adds tracing to auth requests
func (i *Instrumentation) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := i.tracer.Start(r.Context(), "auth.request",
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				attribute.String("http.method", r.Method),
				attribute.String("http.path", r.URL.Path),
				attribute.String("http.user_agent", r.UserAgent()),
			),
		)
		defer span.End()

		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Call the next handler with traced context
		next.ServeHTTP(wrapped, r.WithContext(ctx))

		// Record response attributes
		span.SetAttributes(attribute.Int("http.status_code", wrapped.statusCode))

		if wrapped.statusCode >= 400 {
			span.SetStatus(codes.Error, http.StatusText(wrapped.statusCode))
		}
	})
}

// responseWriter wraps http.ResponseWriter to capture the status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// StartSpan starts a new span for an auth operation
func (i *Instrumentation) StartSpan(r *http.Request, operationName string, attrs ...attribute.KeyValue) (trace.Span, *http.Request) {
	ctx, span := i.tracer.Start(r.Context(), operationName,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attrs...),
	)
	return span, r.WithContext(ctx)
}

// SpanFromRequest returns the current span from the request context
func SpanFromRequest(r *http.Request) trace.Span {
	return trace.SpanFromContext(r.Context())
}

// TraceSignUp adds tracing to sign-up operations
func (i *Instrumentation) TraceSignUp(r *http.Request, email string) (trace.Span, *http.Request) {
	return i.StartSpan(r, "auth.signup",
		attribute.String("auth.email_domain", extractDomain(email)),
	)
}

// TraceSignIn adds tracing to sign-in operations
func (i *Instrumentation) TraceSignIn(r *http.Request, email string) (trace.Span, *http.Request, time.Time) {
	span, req := i.StartSpan(r, "auth.signin",
		attribute.String("auth.email_domain", extractDomain(email)),
	)
	return span, req, time.Now()
}

// TraceSignOut adds tracing to sign-out operations
func (i *Instrumentation) TraceSignOut(r *http.Request, userID string) (trace.Span, *http.Request) {
	return i.StartSpan(r, "auth.signout",
		attribute.String("auth.user_id", userID),
	)
}

// TracePasswordReset adds tracing to password reset operations
func (i *Instrumentation) TracePasswordReset(r *http.Request) (trace.Span, *http.Request) {
	return i.StartSpan(r, "auth.password.reset")
}

// TracePasswordChange adds tracing to password change operations
func (i *Instrumentation) TracePasswordChange(r *http.Request, userID string) (trace.Span, *http.Request) {
	return i.StartSpan(r, "auth.password.change",
		attribute.String("auth.user_id", userID),
	)
}

// TraceEmailVerify adds tracing to email verification operations
func (i *Instrumentation) TraceEmailVerify(r *http.Request) (trace.Span, *http.Request) {
	return i.StartSpan(r, "auth.email.verify")
}

// TraceOAuthBegin adds tracing to OAuth flow initiation
func (i *Instrumentation) TraceOAuthBegin(r *http.Request, provider string) (trace.Span, *http.Request) {
	return i.StartSpan(r, "auth.oauth.begin",
		attribute.String("auth.oauth.provider", provider),
	)
}

// TraceOAuthCallback adds tracing to OAuth callback handling
func (i *Instrumentation) TraceOAuthCallback(r *http.Request, provider string) (trace.Span, *http.Request) {
	return i.StartSpan(r, "auth.oauth.callback",
		attribute.String("auth.oauth.provider", provider),
	)
}

// TraceTokenGenerate adds tracing to token generation
func (i *Instrumentation) TraceTokenGenerate(r *http.Request, grantType string) (trace.Span, *http.Request) {
	return i.StartSpan(r, "auth.token.generate",
		attribute.String("auth.token.grant_type", grantType),
	)
}

// TraceTokenRefresh adds tracing to token refresh
func (i *Instrumentation) TraceTokenRefresh(r *http.Request) (trace.Span, *http.Request) {
	return i.StartSpan(r, "auth.token.refresh")
}

// TraceTokenRevoke adds tracing to token revocation
func (i *Instrumentation) TraceTokenRevoke(r *http.Request) (trace.Span, *http.Request) {
	return i.StartSpan(r, "auth.token.revoke")
}

// TraceAdminOperation adds tracing to admin operations
func (i *Instrumentation) TraceAdminOperation(r *http.Request, operation, targetUserID string) (trace.Span, *http.Request) {
	return i.StartSpan(r, "auth.admin."+operation,
		attribute.String("auth.admin.operation", operation),
		attribute.String("auth.admin.target_user_id", targetUserID),
	)
}

// RecordError records an error on the current span
func RecordError(span trace.Span, err error) {
	if err != nil && span != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
}

// RecordSuccess marks the span as successful
func RecordSuccess(span trace.Span) {
	if span != nil {
		span.SetStatus(codes.Ok, "success")
	}
}

// SetUserID adds user ID to the current span
func SetUserID(span trace.Span, userID string) {
	if span != nil {
		span.SetAttributes(attribute.String("auth.user_id", userID))
	}
}

// extractDomain extracts the domain from an email address for safe logging
func extractDomain(email string) string {
	for i := len(email) - 1; i >= 0; i-- {
		if email[i] == '@' {
			return email[i+1:]
		}
	}
	return "unknown"
}
