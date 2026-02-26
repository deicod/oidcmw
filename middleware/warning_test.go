package middleware

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/deicod/oidcmw/config"
	testissuer "github.com/deicod/oidcmw/testutil/issuer"
	"github.com/stretchr/testify/require"
)

func TestMiddleware_LogsWarningForEmptyAudiences(t *testing.T) {
	issuer := testissuer.New(t)
	t.Cleanup(issuer.Close)

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	cfg := config.Config{
		Issuer: issuer.Issuer(),
		Logger: logger,
		// Audiences is intentionally empty
	}

	_, err := NewMiddleware(cfg)
	require.NoError(t, err)

	require.Contains(t, buf.String(), "security warning: no audiences configured")
}
