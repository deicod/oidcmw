package config

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFromEnv(t *testing.T) {
	t.Setenv("OIDC_ISSUER", "https://issuer")
	t.Setenv("OIDC_AUDIENCES", "one,two")
	t.Setenv("OIDC_TOKEN_TYPES", "Bearer")
	t.Setenv("OIDC_AUTHORIZED_PARTIES", "spa")
	t.Setenv("OIDC_CLOCK_SKEW", "45s")
	t.Setenv("OIDC_UNAUTHORIZED_STATUS_CODE", "418")
	t.Setenv("OIDC_ALLOW_ANONYMOUS_REQUESTS", "true")
	t.Setenv("OIDC_TOKEN_SOURCES", "cookie:session,authorization_header")

	cfg, err := FromEnv("OIDC")
	require.NoError(t, err)
	require.Equal(t, "https://issuer", cfg.Issuer)
	require.Equal(t, []string{"one", "two"}, cfg.Audiences)
	require.Equal(t, []string{"Bearer"}, cfg.TokenTypes)
	require.Equal(t, []string{"spa"}, cfg.AuthorizedParties)
	require.Equal(t, 45*time.Second, cfg.ClockSkew)
	require.Equal(t, 418, cfg.UnauthorizedStatusCode)
	require.True(t, cfg.AllowAnonymousRequests)
	require.Len(t, cfg.TokenSources, 2)
}

func TestFromFileYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := []byte(`issuer: https://issuer
audiences: ["service"]
authorized_parties: ["spa"]
clock_skew: 1m
unauthorized_status_code: 401
allow_anonymous_requests: true
token_sources:
  - type: cookie
    name: access
  - type: authorization_header
`)
	require.NoError(t, os.WriteFile(path, data, 0o600))

	cfg, err := FromFile(path)
	require.NoError(t, err)
	require.Equal(t, "https://issuer", cfg.Issuer)
	require.Equal(t, []string{"service"}, cfg.Audiences)
	require.True(t, cfg.AllowAnonymousRequests)
	require.Len(t, cfg.TokenSources, 2)
}

func TestLoadPrecedence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	data := []byte(`{
                "issuer": "https://file",
                "audiences": ["file"],
                "token_sources": [
                        {"type": "authorization_header"}
                ],
                "allow_anonymous_requests": true
        }`)
	require.NoError(t, os.WriteFile(path, data, 0o600))

	t.Setenv("APP_ISSUER", "https://env")
	t.Setenv("APP_AUDIENCES", "env")
	t.Setenv("APP_TOKEN_SOURCES", "query:token")
	t.Setenv("APP_ALLOW_ANONYMOUS_REQUESTS", "false")

	cfg, err := Load(LoadOptions{File: path, EnvPrefix: "APP"})
	require.NoError(t, err)
	require.Equal(t, "https://env", cfg.Issuer)
	require.Equal(t, []string{"env"}, cfg.Audiences)
	require.False(t, cfg.AllowAnonymousRequests)
	require.Len(t, cfg.TokenSources, 1)

	req := httptest.NewRequest(http.MethodGet, "/?token=value", nil)
	token, err := cfg.TokenSources[0].Extract(req)
	require.NoError(t, err)
	require.Equal(t, "value", token)
}

func TestMergeAppendsValidators(t *testing.T) {
	base := Config{Issuer: "base", ClaimsValidators: []ClaimsValidator{func(context.Context, map[string]any) error { return nil }}}
	override := Config{Issuer: "override", ClaimsValidators: []ClaimsValidator{func(context.Context, map[string]any) error { return nil }}}

	merged := Merge(base, override)
	require.Equal(t, "override", merged.Issuer)
	require.Len(t, merged.ClaimsValidators, 2)
}
