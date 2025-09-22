package middleware

import (
	"context"

	"github.com/deicod/oidcmw/viewer"
)

type contextKey string

const (
	claimsContextKey contextKey = "oidcmw-claims"
)

// contextWithViewer stores the viewer and validated claims in the request context.
func contextWithViewer(ctx context.Context, v *viewer.Viewer) context.Context {
	ctx = viewer.WithViewer(ctx, v)
	claims := v.RawClaims()
	if claims == nil {
		claims = map[string]any{}
	}
	return context.WithValue(ctx, claimsContextKey, claims)
}

// ClaimsFromContext retrieves previously validated token claims from a context.
func ClaimsFromContext(ctx context.Context) (map[string]any, bool) {
	if ctx == nil {
		return nil, false
	}
	claims, ok := ctx.Value(claimsContextKey).(map[string]any)
	if ok {
		return claims, true
	}
	v, err := viewer.FromContext(ctx)
	if err != nil {
		return nil, false
	}
	raw := v.RawClaims()
	if len(raw) == 0 {
		return nil, false
	}
	return raw, true
}
