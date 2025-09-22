package middleware

import "context"

type contextKey string

const (
	claimsContextKey contextKey = "oidcmw-claims"
)

// contextWithClaims stores the validated claims in the request context.
func contextWithClaims(ctx context.Context, claims map[string]any) context.Context {
	return context.WithValue(ctx, claimsContextKey, claims)
}

// ClaimsFromContext retrieves previously validated token claims from a context.
func ClaimsFromContext(ctx context.Context) (map[string]any, bool) {
	claims, ok := ctx.Value(claimsContextKey).(map[string]any)
	return claims, ok
}
