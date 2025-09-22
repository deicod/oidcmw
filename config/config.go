package config

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

// Config captures the runtime configuration for the OIDC middleware.
type Config struct {
	// Issuer is the base URL of the identity provider and is required.
	Issuer string

	// Audiences restricts accepted audience (aud) claims. When empty all audiences are allowed.
	Audiences []string

	// TokenTypes restricts accepted token type (typ) claims. When empty all token types are allowed.
	TokenTypes []string

	// AuthorizedParties restricts accepted authorized party (azp) claims. When empty all parties are allowed.
	AuthorizedParties []string

	// HTTPClient is an optional client used for discovery and JWKS retrieval.
	HTTPClient *http.Client

	// ClockSkew configures the allowed difference between issuer and service clocks when validating temporal claims.
	ClockSkew time.Duration

	// UnauthorizedStatusCode is used when a request fails authentication.
	UnauthorizedStatusCode int

	// ErrorResponseBuilder allows customizing the response body emitted for authentication errors.
	// The returned value must be JSON serializable.
	ErrorResponseBuilder ErrorResponseBuilder

	// Now, when provided, overrides the source of the current time. Primarily used for testing.
	Now func() time.Time
}

// ErrorResponseBuilder creates a structured payload for authentication failures.
type ErrorResponseBuilder func(code, description string) any

// DefaultErrorResponseBuilder returns an RFC 6750 inspired response body.
func DefaultErrorResponseBuilder(code, description string) any {
	body := map[string]string{"error": code}
	if description != "" {
		body["error_description"] = description
	}
	return body
}

// SetDefaults populates unset configuration options with sensible defaults.
func (c *Config) SetDefaults() {
	if c.ClockSkew == 0 {
		c.ClockSkew = 30 * time.Second
	}
	if c.UnauthorizedStatusCode == 0 {
		c.UnauthorizedStatusCode = http.StatusUnauthorized
	}
	if c.ErrorResponseBuilder == nil {
		c.ErrorResponseBuilder = DefaultErrorResponseBuilder
	}
	if len(c.TokenTypes) == 0 {
		c.TokenTypes = []string{"Bearer"}
	}
}

// Validate ensures the configuration is usable.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Issuer) == "" {
		return errors.New("config: issuer is required")
	}
	return nil
}
