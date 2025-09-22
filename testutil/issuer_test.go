package testutil

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/deicod/oidcmw/config"
	internaloidc "github.com/deicod/oidcmw/internal/oidc"
	"github.com/stretchr/testify/require"
)

func TestIssuer_SignTokenValidates(t *testing.T) {
	issuer := NewIssuer(t)

	cfg := config.Config{
		Issuer:            issuer.URL(),
		Audiences:         []string{"account"},
		AuthorizedParties: []string{"spa"},
	}

	validator, err := internaloidc.NewValidator(context.Background(), cfg)
	require.NoError(t, err)

	now := time.Now().Add(-time.Minute)
	claims := map[string]any{
		"iss": issuer.URL(),
		"sub": "subject",
		"aud": "account",
		"exp": now.Add(2 * time.Minute).Unix(),
		"iat": now.Unix(),
		"azp": "spa",
	}

	token := issuer.SignToken(claims)

	_, err = validator.Validate(context.Background(), token)
	require.NoError(t, err)
}

func TestIssuer_ExposesJWKS(t *testing.T) {
	issuer := NewIssuer(t)

	resp, err := http.Get(issuer.URL() + "/jwks")
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestSignTokenWithKey_UsesCustomKey(t *testing.T) {
	key := GenerateRSAKey(t, 2048)

	claims := map[string]any{"sub": "subject"}
	token := SignTokenWithKey(t, key, "custom", claims)
	require.NotEmpty(t, token)
}
