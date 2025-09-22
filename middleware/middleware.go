package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/deicod/oidcmw/config"
	internaloidc "github.com/deicod/oidcmw/internal/oidc"
	"github.com/deicod/oidcmw/tokensource"
	"github.com/deicod/oidcmw/viewer"
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
			rawToken, err := extractToken(r, sources)
			if err != nil {
				if errors.Is(err, tokensource.ErrNotFound) {
					respond(w, cfg, newAuthError(errorCodeInvalidRequest, cfg.UnauthorizedStatusCode, "missing bearer token", err))
					return
				}
				respond(w, cfg, newAuthError(errorCodeServerError, http.StatusInternalServerError, "token extraction failed", err))
				return
			}

			validated, err := validator.Validate(r.Context(), rawToken)
			if err != nil {
				handleValidationError(w, cfg, err)
				return
			}

			v := viewer.FromClaims(validated.Claims)
			ctx := contextWithViewer(r.Context(), v)
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

func handleValidationError(w http.ResponseWriter, cfg config.Config, err error) {
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
			respond(w, cfg, newAuthError(errorCodeInvalidToken, cfg.UnauthorizedStatusCode, "token validation failed", vErr))
			return
		default:
			respond(w, cfg, newAuthError(errorCodeServerError, http.StatusInternalServerError, "token validation error", vErr))
			return
		}
	}
	respond(w, cfg, newAuthError(errorCodeServerError, http.StatusInternalServerError, "token validation error", err))
}

func respond(w http.ResponseWriter, cfg config.Config, authErr authError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(authErr.status)

	body := cfg.ErrorResponseBuilder(string(authErr.code), authErr.description)
	_ = json.NewEncoder(w).Encode(body)
}
