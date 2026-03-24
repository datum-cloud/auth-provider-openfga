package webhook

import (
	"context"
	"fmt"
	"math/rand/v2"
)

type contextKey int

const (
	requestIDKey contextKey = iota
)

// requestIDFromContext retrieves the request ID stored in ctx. It returns an
// empty string if no request ID is present.
func requestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}

// contextWithRequestID stores a request ID in ctx and returns the new context.
func contextWithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

// generateRequestID creates a random hex request ID. If X-Request-ID header
// value is provided and non-empty, it is returned as-is.
func generateRequestID(headerValue string) string {
	if headerValue != "" {
		return headerValue
	}
	// 8 random bytes → 16 hex characters, sufficient for request correlation.
	return fmt.Sprintf("%016x", rand.Uint64())
}
