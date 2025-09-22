package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/deicod/oidcmw/config"
	testissuer "github.com/deicod/oidcmw/internal/testutil/issuer"
	"github.com/deicod/oidcmw/tokensource"
	"github.com/deicod/oidcmw/viewer"
	"github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestMiddleware_AllowsValidToken(t *testing.T) {
	issuer := testissuer.New(t)
	t.Cleanup(issuer.Close)

	cfg := config.Config{
		Issuer:            issuer.Issuer(),
		Audiences:         []string{"account"},
		AuthorizedParties: []string{"spa"},
	}

	mw, err := NewMiddleware(cfg)
	require.NoError(t, err)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := ClaimsFromContext(r.Context())
		require.True(t, ok)
		require.Equal(t, "alice", claims["preferred_username"])

		v, err := viewer.FromContext(r.Context())
		require.NoError(t, err)
		require.Equal(t, "subject", v.Subject)
		require.Equal(t, "alice", v.PreferredUsername)
		require.Equal(t, "alice@example.com", v.Email)
		require.True(t, v.HasRealmRole("offline_access"))
		require.True(t, v.HasResourceRole("account", "view-profile"))
		require.True(t, v.HasAnyScope("email"))
		w.WriteHeader(http.StatusNoContent)
	}))

	now := time.Now().Add(-1 * time.Minute)
	claims := map[string]any{
		"iss":                issuer.Issuer(),
		"sub":                "subject",
		"aud":                "account",
		"exp":                now.Add(2 * time.Minute).Unix(),
		"iat":                now.Unix(),
		"nbf":                now.Unix(),
		"typ":                "Bearer",
		"azp":                "spa",
		"preferred_username": "alice",
		"email":              "alice@example.com",
		"realm_access": map[string]any{
			"roles": []any{"default-roles-dev", "offline_access"},
		},
		"resource_access": map[string]any{
			"account": map[string]any{
				"roles": []string{"manage-account", "view-profile"},
			},
		},
		"scope": "openid email profile",
	}

	token := issuer.SignToken(t, claims)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusNoContent, rr.Code)
}

func TestMiddleware_RejectsInvalidSignature(t *testing.T) {
	issuer := testissuer.New(t)
	t.Cleanup(issuer.Close)

	mw, err := NewMiddleware(config.Config{Issuer: issuer.Issuer(), Audiences: []string{"account"}})
	require.NoError(t, err)

	handler := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler should not be invoked")
	}))

	now := time.Now()
	claims := map[string]any{
		"iss": issuer.Issuer(),
		"sub": "subject",
		"aud": "account",
		"exp": now.Add(time.Minute).Unix(),
		"iat": now.Add(-time.Minute).Unix(),
		"typ": "Bearer",
	}

	token := testissuer.SignWithRandomKey(t, claims)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusUnauthorized, rr.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	require.Equal(t, "invalid_token", body["error"])
}

func TestMiddleware_RejectsExpiredToken(t *testing.T) {
	issuer := testissuer.New(t)
	t.Cleanup(issuer.Close)

	mw, err := NewMiddleware(config.Config{Issuer: issuer.Issuer(), Audiences: []string{"account"}})
	require.NoError(t, err)

	handler := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler should not be invoked")
	}))

	now := time.Now().Add(-2 * time.Minute)
	claims := map[string]any{
		"iss": issuer.Issuer(),
		"sub": "subject",
		"aud": "account",
		"exp": now.Unix(),
		"iat": now.Add(-time.Minute).Unix(),
		"typ": "Bearer",
	}

	token := issuer.SignToken(t, claims)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusUnauthorized, rr.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	require.Equal(t, "invalid_token", body["error"])
}

func TestMiddleware_JWKSFetchFailure(t *testing.T) {
	issuer := testissuer.New(t)
	cfg := config.Config{Issuer: issuer.Issuer(), Audiences: []string{"account"}}
	mw, err := NewMiddleware(cfg)
	require.NoError(t, err)

	handler := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler should not be invoked")
	}))

	now := time.Now()
	claims := map[string]any{
		"iss": issuer.Issuer(),
		"sub": "subject",
		"aud": "account",
		"exp": now.Add(time.Minute).Unix(),
		"iat": now.Add(-time.Minute).Unix(),
		"typ": "Bearer",
	}

	token := issuer.SignToken(t, claims)
	issuer.Close()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusUnauthorized, rr.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	require.Equal(t, "invalid_token", body["error"])
}

func TestMiddleware_RejectsMalformedToken(t *testing.T) {
	issuer := testissuer.New(t)
	t.Cleanup(issuer.Close)

	mw, err := NewMiddleware(config.Config{Issuer: issuer.Issuer()})
	require.NoError(t, err)

	handler := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler should not be invoked")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer not-a-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusUnauthorized, rr.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	require.Equal(t, "invalid_token", body["error"])
}

func TestMiddleware_RejectsMissingAuthorization(t *testing.T) {
	issuer := testissuer.New(t)
	t.Cleanup(issuer.Close)

	mw, err := NewMiddleware(config.Config{Issuer: issuer.Issuer()})
	require.NoError(t, err)

	handler := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler should not be invoked")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusUnauthorized, rr.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	require.Equal(t, "invalid_request", body["error"])
}

func TestMiddleware_CustomTokenSources(t *testing.T) {
	issuer := testissuer.New(t)
	t.Cleanup(issuer.Close)

	cfg := config.Config{
		Issuer:    issuer.Issuer(),
		Audiences: []string{"account"},
		TokenSources: []tokensource.Source{
			tokensource.Cookie("session"),
			tokensource.AuthorizationHeader(),
		},
	}

	mw, err := NewMiddleware(cfg)
	require.NoError(t, err)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	now := time.Now()
	claims := map[string]any{
		"iss": issuer.Issuer(),
		"sub": "subject",
		"aud": "account",
		"exp": now.Add(time.Minute).Unix(),
		"iat": now.Add(-time.Minute).Unix(),
	}

	token := issuer.SignToken(t, claims)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: token})
	req.Header.Set("Authorization", "Bearer invalid")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusNoContent, rr.Code)
}

func TestMiddleware_CustomClaimsValidator(t *testing.T) {
	issuer := testissuer.New(t)
	t.Cleanup(issuer.Close)

	var invoked bool
	cfg := config.Config{
		Issuer:    issuer.Issuer(),
		Audiences: []string{"account"},
		ClaimsValidators: []config.ClaimsValidator{
			func(ctx context.Context, claims map[string]any) error {
				invoked = true
				if claims["preferred_username"] != "alice" {
					return fmt.Errorf("unexpected subject")
				}
				return nil
			},
		},
	}

	mw, err := NewMiddleware(cfg)
	require.NoError(t, err)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	now := time.Now()
	claims := map[string]any{
		"iss":                issuer.Issuer(),
		"sub":                "subject",
		"aud":                "account",
		"exp":                now.Add(time.Minute).Unix(),
		"iat":                now.Add(-time.Minute).Unix(),
		"preferred_username": "alice",
	}

	token := issuer.SignToken(t, claims)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	require.True(t, invoked)
	require.Equal(t, http.StatusOK, rr.Code)
}

func TestMiddleware_CustomClaimsValidatorRejects(t *testing.T) {
	issuer := testissuer.New(t)
	t.Cleanup(issuer.Close)

	cfg := config.Config{
		Issuer:    issuer.Issuer(),
		Audiences: []string{"account"},
		ClaimsValidators: []config.ClaimsValidator{
			func(ctx context.Context, claims map[string]any) error {
				return fmt.Errorf("denied")
			},
		},
	}

	mw, err := NewMiddleware(cfg)
	require.NoError(t, err)

	handler := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler should not be invoked")
	}))

	now := time.Now()
	claims := map[string]any{
		"iss": issuer.Issuer(),
		"sub": "subject",
		"aud": "account",
		"exp": now.Add(time.Minute).Unix(),
		"iat": now.Add(-time.Minute).Unix(),
	}

	token := issuer.SignToken(t, claims)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusUnauthorized, rr.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	require.Equal(t, "invalid_token", body["error"])
}

func TestMiddleware_RecordsMetricsOnSuccess(t *testing.T) {
	issuer := testissuer.New(t)
	t.Cleanup(issuer.Close)

	recorder := &capturingMetrics{}
	spanRecorder := tracetest.NewSpanRecorder()
	tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spanRecorder))
	t.Cleanup(func() {
		_ = tracerProvider.Shutdown(context.Background())
	})
	cfg := config.Config{
		Issuer:          issuer.Issuer(),
		Audiences:       []string{"account"},
		MetricsRecorder: recorder,
		Tracer:          tracerProvider.Tracer("middleware-test"),
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	mw, err := NewMiddleware(cfg)
	require.NoError(t, err)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	now := time.Now()
	claims := map[string]any{
		"iss": issuer.Issuer(),
		"sub": "subject",
		"aud": "account",
		"exp": now.Add(time.Minute).Unix(),
		"iat": now.Add(-time.Minute).Unix(),
	}

	token := issuer.SignToken(t, claims)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusNoContent, rr.Code)
	require.Len(t, recorder.events, 1)
	require.Equal(t, config.MetricsOutcomeSuccess, recorder.events[0].Outcome)
	require.Empty(t, recorder.events[0].ErrorCode)

	spans := spanRecorder.Ended()
	require.Len(t, spans, 1)
}

func TestMiddleware_RecordsMetricsOnFailure(t *testing.T) {
	issuer := testissuer.New(t)
	t.Cleanup(issuer.Close)

	recorder := &capturingMetrics{}
	spanRecorder := tracetest.NewSpanRecorder()
	tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spanRecorder))
	t.Cleanup(func() {
		_ = tracerProvider.Shutdown(context.Background())
	})
	cfg := config.Config{
		Issuer:          issuer.Issuer(),
		MetricsRecorder: recorder,
		Tracer:          tracerProvider.Tracer("middleware-test"),
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	mw, err := NewMiddleware(cfg)
	require.NoError(t, err)

	handler := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler should not be invoked")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusUnauthorized, rr.Code)
	require.Len(t, recorder.events, 1)
	require.Equal(t, config.MetricsOutcomeFailure, recorder.events[0].Outcome)
	require.Equal(t, "invalid_request", recorder.events[0].ErrorCode)

	spans := spanRecorder.Ended()
	require.Len(t, spans, 1)
}

type capturingMetrics struct {
	events []config.MetricsEvent
}

func (c *capturingMetrics) RecordValidation(_ context.Context, event config.MetricsEvent) {
	c.events = append(c.events, event)
}
