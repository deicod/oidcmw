package config

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/deicod/oidcmw/tokensource"
	"go.opentelemetry.io/otel/trace"
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
	// When unset, SetDefaults installs a client with reasonable timeouts suitable for
	// communicating with identity providers.
	HTTPClient *http.Client

	// ClockSkew configures the allowed difference between issuer and service clocks when validating temporal claims.
	ClockSkew time.Duration

	// UnauthorizedStatusCode is used when a request fails authentication.
	UnauthorizedStatusCode int

	// AllowAnonymousRequests permits the middleware to pass through requests that
	// do not present a bearer token. When enabled, downstream handlers can use
	// viewer.IsAuthenticated to distinguish anonymous callers from authenticated
	// ones.
	AllowAnonymousRequests bool

	// ErrorResponseBuilder allows customizing the response body emitted for authentication errors.
	// The returned value must be JSON serializable.
	ErrorResponseBuilder ErrorResponseBuilder

	// Now, when provided, overrides the source of the current time. Primarily used for testing.
	Now func() time.Time

	// TokenSources controls the order and implementation of token extraction. When empty a default
	// Authorization header source is used. Custom sources should return tokens in the raw string form.
	TokenSources []tokensource.Source

	// ClaimsValidators allows callers to provide additional validation logic for decoded claims.
	ClaimsValidators []ClaimsValidator

	// MetricsRecorder, when provided, captures authentication outcomes and latency information.
	MetricsRecorder MetricsRecorder

	// Tracer emits OpenTelemetry spans around validation attempts when configured.
	Tracer trace.Tracer

	// Logger records structured log entries for authentication successes and failures. When nil a default slog logger is used.
	Logger *slog.Logger

	// ViewerFactory constructs the principal instance placed on the request context. When nil a default
	// factory returning a *viewer.Viewer is used.
	ViewerFactory ViewerFactory

	// ViewerContextBinder attaches the constructed viewer and claims to the request context. When nil a default
	// binder that installs the viewer via viewer.WithViewer and stores the claims map is used.
	ViewerContextBinder ViewerContextBinder

	allowAnonymousRequestsConfigured bool
}

// ClaimsValidator performs additional validation on decoded token claims.
type ClaimsValidator func(ctx context.Context, claims map[string]any) error

// ErrorResponseBuilder creates a structured payload for authentication failures.
type ErrorResponseBuilder func(code, description string) any

// MetricsOutcome classifies the result of a validation attempt.
type MetricsOutcome string

const (
	// MetricsOutcomeSuccess represents a successful authentication attempt.
	MetricsOutcomeSuccess MetricsOutcome = "success"
	// MetricsOutcomeFailure represents a failed authentication attempt.
	MetricsOutcomeFailure MetricsOutcome = "failure"
)

// MetricsEvent describes the payload reported to a MetricsRecorder.
type MetricsEvent struct {
	Issuer    string
	Outcome   MetricsOutcome
	ErrorCode string
	Duration  time.Duration
}

// MetricsRecorder records authentication metrics.
type MetricsRecorder interface {
	RecordValidation(ctx context.Context, event MetricsEvent)
}

// ViewerFactory constructs a viewer/principal instance from validated claims.
type ViewerFactory func(claims map[string]any) (any, error)

// ViewerContextBinder attaches the viewer and claims to the request context.
type ViewerContextBinder func(ctx context.Context, viewer any, claims map[string]any) context.Context

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
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   5 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   5 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		}
	}
	if c.UnauthorizedStatusCode == 0 {
		c.UnauthorizedStatusCode = http.StatusUnauthorized
	}
	if c.ErrorResponseBuilder == nil {
		c.ErrorResponseBuilder = DefaultErrorResponseBuilder
	}
	if len(c.TokenSources) == 0 {
		c.TokenSources = []tokensource.Source{tokensource.AuthorizationHeader()}
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.AllowAnonymousRequests && !c.allowAnonymousRequestsConfigured {
		c.allowAnonymousRequestsConfigured = true
	}
}

// Validate ensures the configuration is usable.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Issuer) == "" {
		return errors.New("config: issuer is required")
	}
	if len(c.TokenSources) == 0 {
		return errors.New("config: at least one token source must be configured")
	}
	return nil
}
