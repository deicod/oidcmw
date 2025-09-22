package issuer

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFakeIssuerServesDiscoveryAndJWKS(t *testing.T) {
	fi := New(t)
	t.Cleanup(fi.Close)

	resp, err := http.Get(fi.Issuer() + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var doc map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&doc))
	require.Equal(t, fi.Issuer(), doc["issuer"])
	require.Equal(t, fi.JWKSURL(), doc["jwks_uri"])

	jwksResp, err := http.Get(fi.JWKSURL())
	require.NoError(t, err)
	defer jwksResp.Body.Close()
	require.Equal(t, http.StatusOK, jwksResp.StatusCode)

	var jwks map[string]any
	require.NoError(t, json.NewDecoder(jwksResp.Body).Decode(&jwks))
	keys, ok := jwks["keys"].([]any)
	require.True(t, ok)
	require.Len(t, keys, 1)
}

func TestSignToken(t *testing.T) {
	fi := New(t)
	t.Cleanup(fi.Close)

	token := fi.SignToken(t, map[string]any{"iss": fi.Issuer(), "sub": "alice"})
	require.NotEmpty(t, token)
}

func TestSignWithRandomKey(t *testing.T) {
	token := SignWithRandomKey(t, map[string]any{"sub": "alice"})
	require.NotEmpty(t, token)
}
