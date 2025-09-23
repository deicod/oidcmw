package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/deicod/oidcmw/config"
	internaloidc "github.com/deicod/oidcmw/internal/oidc"
	"github.com/deicod/oidcmw/tokensource"
	"github.com/deicod/oidcmw/viewer"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// NewMiddleware constructs an HTTP middleware enforcing OIDC bearer token validation.
func NewMiddleware(cfg config.Config) (func(http.Handler) http.Handler, error) {
	cfg.SetDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	validator, err := internaloidc.NewValidator(context.Background(), cfg)
	if err != nil {
		return nil, err
	}

	sources := append([]tokensource.Source(nil), cfg.TokenSources...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ctx := r.Context()
			ctx, span := startSpan(ctx, cfg.Tracer, cfg.Issuer)
			if span != nil {
				defer span.End()
			}

			rawToken, err := extractToken(r, sources)
			if err != nil {
				if errors.Is(err, tokensource.ErrNotFound) {
					if cfg.AllowAnonymousRequests {
						recordSpan(span, config.MetricsOutcomeSuccess, "", nil)
						recordMetrics(ctx, cfg, start, config.MetricsOutcomeSuccess, "")
						next.ServeHTTP(w, r.WithContext(ctx))
						return
					}
					authErr := newAuthError(errorCodeInvalidRequest, cfg.UnauthorizedStatusCode, "missing bearer token", err)
					logFailure(ctx, cfg.Logger, authErr)
					respond(w, cfg, authErr)
					recordMetrics(ctx, cfg, start, config.MetricsOutcomeFailure, string(authErr.code))
					recordSpan(span, config.MetricsOutcomeFailure, string(authErr.code), err)
					return
				}
				authErr := newAuthError(errorCodeServerError, http.StatusInternalServerError, "token extraction failed", err)
				logFailure(ctx, cfg.Logger, authErr)
				respond(w, cfg, authErr)
				recordMetrics(ctx, cfg, start, config.MetricsOutcomeFailure, string(authErr.code))
				recordSpan(span, config.MetricsOutcomeFailure, string(authErr.code), err)
				return
			}

			validated, err := validator.Validate(ctx, rawToken)
			if err != nil {
				authErr := handleValidationError(w, cfg, err)
				logFailure(ctx, cfg.Logger, authErr)
				recordMetrics(ctx, cfg, start, config.MetricsOutcomeFailure, string(authErr.code))
				recordSpan(span, config.MetricsOutcomeFailure, string(authErr.code), err)
				return
			}

			v := viewer.FromClaims(validated.Claims)
			ctx = contextWithViewer(ctx, v)
			recordSpan(span, config.MetricsOutcomeSuccess, "", nil)
			recordMetrics(ctx, cfg, start, config.MetricsOutcomeSuccess, "")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}, nil
}

func extractToken(r *http.Request, sources []tokensource.Source) (string, error) {
	for _, source := range sources {
		token, err := source.Extract(r)
		if err != nil {
			if errors.Is(err, tokensource.ErrNotFound) {
				continue
			}
			return "", err
		}
		if strings.TrimSpace(token) == "" {
			continue
		}
		return token, nil
	}
	return "", tokensource.ErrNotFound
}

func handleValidationError(w http.ResponseWriter, cfg config.Config, err error) authError {
	var vErr *internaloidc.ValidationError
	if errors.As(err, &vErr) {
		switch vErr.Code {
		case internaloidc.ValidationErrorExpired,
			internaloidc.ValidationErrorNotYetValid,
			internaloidc.ValidationErrorClaimMismatch,
			internaloidc.ValidationErrorMalformedToken,
			internaloidc.ValidationErrorIssuerMismatch,
			internaloidc.ValidationErrorAudienceMismatch,
			internaloidc.ValidationErrorTypeMismatch,
			internaloidc.ValidationErrorAZPMismatch,
			internaloidc.ValidationErrorInvalidToken:
			authErr := newAuthError(errorCodeInvalidToken, cfg.UnauthorizedStatusCode, "token validation failed", vErr)
			respond(w, cfg, authErr)
			return authErr
		default:
			authErr := newAuthError(errorCodeServerError, http.StatusInternalServerError, "token validation error", vErr)
			respond(w, cfg, authErr)
			return authErr
		}
	}
	authErr := newAuthError(errorCodeServerError, http.StatusInternalServerError, "token validation error", err)
	respond(w, cfg, authErr)
	return authErr
}

func respond(w http.ResponseWriter, cfg config.Config, authErr authError) {
	w.Header().Set("Content-Type", "application/json")
	if authErr.status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", wwwAuthenticateHeader(authErr))
	}
	w.WriteHeader(authErr.status)

	body := cfg.ErrorResponseBuilder(string(authErr.code), authErr.description)
	_ = json.NewEncoder(w).Encode(body)
}

func wwwAuthenticateHeader(authErr authError) string {
	var b strings.Builder
	b.WriteString("Bearer error=")
	b.WriteString(strconv.Quote(string(authErr.code)))
	b.WriteString(", error_description=")
	b.WriteString(strconv.Quote(authErr.description))
	return b.String()
}

func logFailure(ctx context.Context, logger *slog.Logger, authErr authError) {
	if logger == nil {
		return
	}
	logger.WarnContext(ctx, "authentication failed",
		slog.String("error_code", string(authErr.code)),
		slog.String("description", authErr.description),
		slog.Any("cause", authErr.cause),
	)
}

func recordMetrics(ctx context.Context, cfg config.Config, start time.Time, outcome config.MetricsOutcome, errorCode string) {
	if cfg.MetricsRecorder == nil {
		return
	}
	cfg.MetricsRecorder.RecordValidation(ctx, config.MetricsEvent{
		Issuer:    cfg.Issuer,
		Outcome:   outcome,
		ErrorCode: errorCode,
		Duration:  time.Since(start),
	})
}

func startSpan(ctx context.Context, tracer trace.Tracer, issuer string) (context.Context, trace.Span) {
	if tracer == nil {
		return ctx, nil
	}
	ctx, span := tracer.Start(ctx, "oidcmw.authenticate")
	span.SetAttributes(attribute.String("oidcmw.issuer", issuer))
	return ctx, span
}

func recordSpan(span trace.Span, outcome config.MetricsOutcome, errorCode string, err error) {
	if span == nil {
		return
	}
	span.SetAttributes(attribute.String("oidcmw.outcome", string(outcome)))
	if errorCode != "" {
		span.SetAttributes(attribute.String("oidcmw.error_code", errorCode))
	}
	if err != nil {
		span.RecordError(err)
	}
}
