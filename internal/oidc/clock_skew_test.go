package oidc

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/deicod/oidcmw/config"
	"github.com/deicod/oidcmw/testutil/issuer"
)

func TestClockSkewRespectsExpiry(t *testing.T) {
	// Setup fake issuer
	fi := issuer.New(t)
	defer fi.Close()

	// Config with ClockSkew
	cfg := config.Config{
		Issuer:    fi.Issuer(),
		ClockSkew: time.Minute,
		HTTPClient: http.DefaultClient,
		Audiences: []string{"test-aud"},
	}

	validator, err := NewValidator(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}

	// Create a token expired 30 seconds ago.
	// Skew is 1 minute.
	// So it should be valid if skew is respected.
	now := time.Now()
	claims := map[string]any{
		"iss": fi.Issuer(),
		"sub": "test-user",
		"aud": "test-aud",
		"exp": now.Add(-30 * time.Second).Unix(),
		"iat": now.Add(-1 * time.Hour).Unix(),
	}

	token := fi.SignToken(t, claims)

	// Validate
	_, err = validator.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("Validation failed for token within skew: %v", err)
	}

	// Create a token expired 2 minutes ago (beyond 1 minute skew).
	claims = map[string]any{
		"iss": fi.Issuer(),
		"sub": "test-user-expired",
		"aud": "test-aud",
		"exp": now.Add(-2 * time.Minute).Unix(),
		"iat": now.Add(-1 * time.Hour).Unix(),
	}

	token = fi.SignToken(t, claims)

	// Validate - should fail
	_, err = validator.Validate(context.Background(), token)
	if err == nil {
		t.Fatal("Validation succeeded for token expired beyond skew, but should have failed")
	}

	vErr, ok := err.(*ValidationError)
	if !ok || vErr.Code != ValidationErrorExpired {
		t.Fatalf("Expected ValidationErrorExpired, got: %v", err)
	}
}
