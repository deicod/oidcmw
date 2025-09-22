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
	tests := []struct {
		name      string
		scheme    string
		header    string
		wantToken string
		wantErr   error
	}{
		{
			name:      "exact match",
			scheme:    "Custom",
			header:    "Custom token",
			wantToken: "token",
		},
		{
			name:      "case insensitive header",
			scheme:    "Custom",
			header:    "CUSTOM token",
			wantToken: "token",
		},
		{
			name:      "case insensitive scheme",
			scheme:    "custom",
			header:    "Custom token",
			wantToken: "token",
		},
		{
			name:    "scheme only without separator",
			scheme:  "Custom",
			header:  "Custom",
			wantErr: ErrNotFound,
		},
		{
			name:    "missing space after scheme",
			scheme:  "Custom",
			header:  "Customtoken",
			wantErr: ErrNotFound,
		},
		{
			name:    "missing token",
			scheme:  "Custom",
			header:  "Custom ",
			wantErr: ErrNotFound,
		},
		{
			name:    "header not present",
			scheme:  "Custom",
			wantErr: ErrNotFound,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}

			token, err := AuthorizationHeaderWithScheme(tc.scheme).Extract(req)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.wantToken, token)
		})
	}
}

func TestHeaderWithScheme(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		scheme    string
		wantToken string
		wantErr   error
	}{
		{
			name:      "exact match",
			header:    "Token scheme-value",
			scheme:    "Token",
			wantToken: "scheme-value",
		},
		{
			name:      "case insensitive header",
			header:    "TOKEN scheme-value",
			scheme:    "Token",
			wantToken: "scheme-value",
		},
		{
			name:      "case insensitive scheme",
			header:    "Token scheme-value",
			scheme:    "token",
			wantToken: "scheme-value",
		},
		{
			name:    "mismatched scheme",
			header:  "Token scheme-value",
			scheme:  "Bearer",
			wantErr: ErrNotFound,
		},
		{
			name:    "scheme only without separator",
			header:  "Token",
			scheme:  "Token",
			wantErr: ErrNotFound,
		},
		{
			name:    "missing space after scheme",
			header:  "Tokenscheme-value",
			scheme:  "Token",
			wantErr: ErrNotFound,
		},
		{
			name:    "header not present",
			scheme:  "Token",
			wantErr: ErrNotFound,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.header != "" {
				req.Header.Set("X-Auth", tc.header)
			}

			token, err := HeaderWithScheme("X-Auth", tc.scheme).Extract(req)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.wantToken, token)
		})
	}
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
