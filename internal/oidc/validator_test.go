package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/deicod/oidcmw/config"
)

func TestValidateIssuerMismatchIsCaseSensitive(t *testing.T) {
	const configuredIssuer = "https://issuer.example.com"
	tokenIssuer := "https://ISSUER.example.com"
	now := time.Unix(1_700_000_000, 0).UTC()

	claims := map[string]any{
		"iss": tokenIssuer,
		"sub": "subject",
		"aud": []string{"audience"},
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Add(-time.Minute).Unix(),
	}

	rawToken := createUnsignedToken(t, claims)

	verifier := oidc.NewVerifier(configuredIssuer, nil, &oidc.Config{
		SkipClientIDCheck:          true,
		SkipIssuerCheck:            true,
		SkipExpiryCheck:            true,
		InsecureSkipSignatureCheck: true,
	})

	validator := &Validator{
		verifier: verifier,
		config: config.Config{
			Issuer: configuredIssuer,
		},
		now: func() time.Time { return now },
	}

	_, err := validator.Validate(context.Background(), rawToken)
	if err == nil {
		t.Fatal("expected validation error for issuer mismatch")
	}

	vErr, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected ValidationError, got %T", err)
	}

	if vErr.Code != ValidationErrorIssuerMismatch {
		t.Fatalf("expected issuer mismatch error, got %s", vErr.Code)
	}
}

func createUnsignedToken(t *testing.T, claims map[string]any) string {
	t.Helper()

	header := map[string]string{"alg": "none"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}

	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)

	return encodedHeader + "." + encodedPayload + "."
}
