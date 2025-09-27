package middleware

import (
	"context"
	"maps"

	"github.com/deicod/oidcmw/viewer"
)

type contextKey string

const (
	claimsContextKey contextKey = "oidcmw-claims"
)

// WithClaims stores the validated claims in the request context.
func WithClaims(ctx context.Context, claims map[string]any) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	cloned := cloneClaims(claims)
	if cloned == nil {
		cloned = map[string]any{}
	}
	return context.WithValue(ctx, claimsContextKey, cloned)
}

// DefaultViewerContextBinder stores the viewer (when it is a *viewer.Viewer) and validated claims in the request context.
func DefaultViewerContextBinder(ctx context.Context, v any, claims map[string]any) context.Context {
	vv, _ := v.(*viewer.Viewer)
	return contextWithViewer(ctx, vv, claims)
}

func contextWithViewer(ctx context.Context, v *viewer.Viewer, claims map[string]any) context.Context {
	if v != nil {
		ctx = viewer.WithViewer(ctx, v)
		claims = v.RawClaims()
	}
	return WithClaims(ctx, claims)
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

func cloneClaims(claims map[string]any) map[string]any {
	if len(claims) == 0 {
		return nil
	}
	return maps.Clone(claims)
}
