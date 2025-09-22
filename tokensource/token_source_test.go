package tokensource

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthorizationHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer token123")

	token, err := AuthorizationHeader().Extract(req)
	require.NoError(t, err)
	require.Equal(t, "token123", token)
}

func TestAuthorizationHeaderWithScheme(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Custom token")

	token, err := AuthorizationHeaderWithScheme("Custom").Extract(req)
	require.NoError(t, err)
	require.Equal(t, "token", token)
}

func TestHeaderWithScheme(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Auth", "Token scheme-value")

	_, err := HeaderWithScheme("X-Auth", "Bearer").Extract(req)
	require.ErrorIs(t, err, ErrNotFound)

	token, err := HeaderWithScheme("X-Auth", "Token").Extract(req)
	require.NoError(t, err)
	require.Equal(t, "scheme-value", token)
}

func TestCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "cookie-token"})

	token, err := Cookie("session").Extract(req)
	require.NoError(t, err)
	require.Equal(t, "cookie-token", token)
}

func TestQuery(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?access=abc", nil)

	token, err := Query("access").Extract(req)
	require.NoError(t, err)
	require.Equal(t, "abc", token)
}

func TestDefinitionBuild(t *testing.T) {
	def := Definition{Type: TypeHeader, Name: "X-Token"}
	src, err := def.Build()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Token", "value")

	token, err := src.Extract(req)
	require.NoError(t, err)
	require.Equal(t, "value", token)
}

func TestParseList(t *testing.T) {
	encodedScheme := url.QueryEscape("Token")
	defs, err := ParseList("authorization_header, header:X-Api-Key:" + encodedScheme + ", cookie:session, query:access")
	require.NoError(t, err)
	require.Len(t, defs, 4)
	require.Equal(t, TypeAuthorizationHeader, defs[0].Type)
	require.Equal(t, TypeHeader, defs[1].Type)
	require.Equal(t, "X-Api-Key", defs[1].Name)
	require.Equal(t, "Token", defs[1].Scheme)
	require.Equal(t, TypeCookie, defs[2].Type)
	require.Equal(t, "session", defs[2].Name)
	require.Equal(t, TypeQuery, defs[3].Type)
	require.Equal(t, "access", defs[3].Name)
}
