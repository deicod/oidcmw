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

func BenchmarkValidate_Success(b *testing.B) {
	const configuredIssuer = "https://issuer.example.com"
	now := time.Now()

	claims := map[string]any{
		"iss": configuredIssuer,
		"sub": "subject",
		"aud": []string{"audience"},
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Add(-time.Minute).Unix(),
		"nbf": now.Add(-time.Minute).Unix(),
	}

	rawToken := createBenchmarkToken(b, claims)

	validator := createBenchmarkValidator(configuredIssuer, now)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := validator.Validate(context.Background(), rawToken)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}

func BenchmarkValidate_FailIssuer(b *testing.B) {
	const configuredIssuer = "https://issuer.example.com"
	now := time.Now()

	claims := map[string]any{
		"iss": "https://wrong.com",
		"sub": "subject",
		"aud": []string{"audience"},
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Add(-time.Minute).Unix(),
	}

	rawToken := createBenchmarkToken(b, claims)

	validator := createBenchmarkValidator(configuredIssuer, now)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := validator.Validate(context.Background(), rawToken)
		if err == nil {
			b.Fatal("expected error")
		}
	}
}

func createBenchmarkValidator(issuer string, now time.Time) *Validator {
	verifier := oidc.NewVerifier(issuer, nil, &oidc.Config{
		SkipClientIDCheck:          true,
		SkipIssuerCheck:            true, // We check manually in Validator
		SkipExpiryCheck:            true, // We check manually in Validator
		InsecureSkipSignatureCheck: true,
	})

	return &Validator{
		verifier: verifier,
		config: config.Config{
			Issuer:    issuer,
			Audiences: []string{"audience"},
		},
		audienceAllowlist: map[string]struct{}{"audience": {}},
		now:               func() time.Time { return now },
	}
}

func createBenchmarkToken(t testing.TB, claims map[string]any) string {
	header := map[string]string{"alg": "none"}
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(claims)

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)

	return encodedHeader + "." + encodedPayload + "."
}
