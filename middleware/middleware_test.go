package middleware

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/deicod/oidcmw/config"
	"github.com/deicod/oidcmw/tokensource"
	"github.com/deicod/oidcmw/viewer"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestMiddleware_AllowsValidToken(t *testing.T) {
	issuer := newTestIssuer(t)
	t.Cleanup(issuer.Close)

	cfg := config.Config{
		Issuer:            issuer.issuer,
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
		"iss":                issuer.issuer,
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

	token := issuer.signToken(t, claims)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusNoContent, rr.Code)
}

func TestMiddleware_RejectsInvalidSignature(t *testing.T) {
	issuer := newTestIssuer(t)
	t.Cleanup(issuer.Close)

	mw, err := NewMiddleware(config.Config{Issuer: issuer.issuer, Audiences: []string{"account"}})
	require.NoError(t, err)

	handler := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler should not be invoked")
	}))

	now := time.Now()
	claims := map[string]any{
		"iss": issuer.issuer,
		"sub": "subject",
		"aud": "account",
		"exp": now.Add(time.Minute).Unix(),
		"iat": now.Add(-time.Minute).Unix(),
		"typ": "Bearer",
	}

	token := signWithDifferentKey(t, claims)

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
	issuer := newTestIssuer(t)
	t.Cleanup(issuer.Close)

	mw, err := NewMiddleware(config.Config{Issuer: issuer.issuer, Audiences: []string{"account"}})
	require.NoError(t, err)

	handler := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler should not be invoked")
	}))

	now := time.Now().Add(-2 * time.Minute)
	claims := map[string]any{
		"iss": issuer.issuer,
		"sub": "subject",
		"aud": "account",
		"exp": now.Unix(),
		"iat": now.Add(-time.Minute).Unix(),
		"typ": "Bearer",
	}

	token := issuer.signToken(t, claims)

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
	issuer := newTestIssuer(t)
	cfg := config.Config{Issuer: issuer.issuer, Audiences: []string{"account"}}
	mw, err := NewMiddleware(cfg)
	require.NoError(t, err)

	handler := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler should not be invoked")
	}))

	now := time.Now()
	claims := map[string]any{
		"iss": issuer.issuer,
		"sub": "subject",
		"aud": "account",
		"exp": now.Add(time.Minute).Unix(),
		"iat": now.Add(-time.Minute).Unix(),
		"typ": "Bearer",
	}

	token := issuer.signToken(t, claims)
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
	issuer := newTestIssuer(t)
	t.Cleanup(issuer.Close)

	mw, err := NewMiddleware(config.Config{Issuer: issuer.issuer})
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
	issuer := newTestIssuer(t)
	t.Cleanup(issuer.Close)

	mw, err := NewMiddleware(config.Config{Issuer: issuer.issuer})
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
	issuer := newTestIssuer(t)
	t.Cleanup(issuer.Close)

	cfg := config.Config{
		Issuer:    issuer.issuer,
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
		"iss": issuer.issuer,
		"sub": "subject",
		"aud": "account",
		"exp": now.Add(time.Minute).Unix(),
		"iat": now.Add(-time.Minute).Unix(),
	}

	token := issuer.signToken(t, claims)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: token})
	req.Header.Set("Authorization", "Bearer invalid")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusNoContent, rr.Code)
}

func TestMiddleware_CustomClaimsValidator(t *testing.T) {
	issuer := newTestIssuer(t)
	t.Cleanup(issuer.Close)

	var invoked bool
	cfg := config.Config{
		Issuer:    issuer.issuer,
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
		"iss":                issuer.issuer,
		"sub":                "subject",
		"aud":                "account",
		"exp":                now.Add(time.Minute).Unix(),
		"iat":                now.Add(-time.Minute).Unix(),
		"preferred_username": "alice",
	}

	token := issuer.signToken(t, claims)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	require.True(t, invoked)
	require.Equal(t, http.StatusOK, rr.Code)
}

func TestMiddleware_CustomClaimsValidatorRejects(t *testing.T) {
	issuer := newTestIssuer(t)
	t.Cleanup(issuer.Close)

	cfg := config.Config{
		Issuer:    issuer.issuer,
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
		"iss": issuer.issuer,
		"sub": "subject",
		"aud": "account",
		"exp": now.Add(time.Minute).Unix(),
		"iat": now.Add(-time.Minute).Unix(),
	}

	token := issuer.signToken(t, claims)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusUnauthorized, rr.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	require.Equal(t, "invalid_token", body["error"])
}

type testIssuer struct {
	server *httptest.Server
	issuer string
	key    *rsa.PrivateKey
	keyID  string
	jwks   []byte
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ti := &testIssuer{key: key, keyID: "test-key"}
	ti.jwks = buildJWKS(t, key, ti.keyID)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]any{
			"issuer":                 ti.issuer,
			"jwks_uri":               ti.issuer + "/jwks",
			"token_endpoint":         ti.issuer + "/token",
			"authorization_endpoint": ti.issuer + "/auth",
		}
		_ = json.NewEncoder(w).Encode(response)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(ti.jwks)
	})

	server := httptest.NewServer(mux)
	ti.server = server
	ti.issuer = server.URL

	return ti
}

func (ti *testIssuer) signToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	token.Header["kid"] = ti.keyID
	signed, err := token.SignedString(ti.key)
	require.NoError(t, err)
	return signed
}

func (ti *testIssuer) Close() {
	if ti.server != nil {
		ti.server.Close()
	}
}

func buildJWKS(t *testing.T, key *rsa.PrivateKey, keyID string) []byte {
	t.Helper()
	n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())

	jwk := map[string]any{
		"kty": "RSA",
		"alg": "RS256",
		"use": "sig",
		"kid": keyID,
		"n":   n,
		"e":   e,
	}

	body, err := json.Marshal(map[string]any{"keys": []any{jwk}})
	require.NoError(t, err)
	return body
}

func signWithDifferentKey(t *testing.T, claims map[string]any) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	token.Header["kid"] = "other"
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}
