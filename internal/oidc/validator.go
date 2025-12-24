package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/deicod/oidcmw/config"
)

// Validator verifies tokens issued by an OpenID Connect provider.
type Validator struct {
	verifier           *oidc.IDTokenVerifier
	config             config.Config
	audienceAllowlist  map[string]struct{}
	tokenTypeAllowlist map[string]struct{}
	azpAllowlist       map[string]struct{}
	now                func() time.Time
	claimsValidators   []config.ClaimsValidator
}

// ValidatedToken encapsulates the validated token and decoded claims.
type ValidatedToken struct {
	Raw       string
	Claims    map[string]any
	Subject   string
	Expiry    time.Time
	IssuedAt  time.Time
	NotBefore *time.Time
}

// NewValidator constructs a Validator using the provided configuration.
func NewValidator(ctx context.Context, cfg config.Config) (*Validator, error) {
	if cfg.HTTPClient == nil {
		return nil, fmt.Errorf("oidc: http client is not configured")
	}

	ctx = oidc.ClientContext(ctx, cfg.HTTPClient)
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: create provider: %w", err)
	}

	oidcConfig := &oidc.Config{
		SkipClientIDCheck: true,
	}

	verifier := provider.Verifier(oidcConfig)
	audiences := toSet(cfg.Audiences, false)
	tokenTypes := toSet(cfg.TokenTypes, true)
	azps := toSet(cfg.AuthorizedParties, false)

	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	return &Validator{
		verifier:           verifier,
		config:             cfg,
		audienceAllowlist:  audiences,
		tokenTypeAllowlist: tokenTypes,
		azpAllowlist:       azps,
		now:                now,
		claimsValidators:   append([]config.ClaimsValidator(nil), cfg.ClaimsValidators...),
	}, nil
}

// Validate verifies the token signature and claims.
func (v *Validator) Validate(ctx context.Context, rawToken string) (*ValidatedToken, error) {
	idToken, err := v.verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, newValidationError(ValidationErrorInvalidToken, "token verification failed", err)
	}
	claims := map[string]any{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, newValidationError(ValidationErrorMalformedToken, "failed to decode token claims", err)
	}

	notBefore, err := parseNotBefore(claims["nbf"])
	if err != nil {
		return nil, newValidationError(ValidationErrorMalformedToken, "invalid not-before claim", err)
	}

	now := v.now()
	if err := v.validateTimes(now, idToken, notBefore); err != nil {
		return nil, err
	}

	if err := v.validateIssuer(claims); err != nil {
		return nil, err
	}
	if err := v.validateAudience(claims); err != nil {
		return nil, err
	}
	if err := v.validateType(claims); err != nil {
		return nil, err
	}
	if err := v.validateAZP(claims); err != nil {
		return nil, err
	}

	if err := v.runCustomValidators(ctx, claims); err != nil {
		return nil, err
	}

	subject, _ := claims["sub"].(string)

	validated := &ValidatedToken{
		Raw:       rawToken,
		Claims:    claims,
		Subject:   subject,
		Expiry:    idToken.Expiry,
		IssuedAt:  idToken.IssuedAt,
		NotBefore: notBefore,
	}

	return validated, nil
}

func (v *Validator) runCustomValidators(ctx context.Context, claims map[string]any) *ValidationError {
	for _, validate := range v.claimsValidators {
		if validate == nil {
			continue
		}
		if err := validate(ctx, claims); err != nil {
			var vErr *ValidationError
			if errors.As(err, &vErr) {
				return vErr
			}
			return newValidationError(ValidationErrorClaimMismatch, "custom claim validation failed", err)
		}
	}
	return nil
}

func (v *Validator) validateTimes(now time.Time, token *oidc.IDToken, notBefore *time.Time) *ValidationError {
	skew := v.config.ClockSkew
	if !token.Expiry.IsZero() {
		if now.After(token.Expiry.Add(skew)) {
			return newValidationError(ValidationErrorExpired, "token has expired", nil)
		}
	}
	if !token.IssuedAt.IsZero() {
		if token.IssuedAt.After(now.Add(skew)) {
			return newValidationError(ValidationErrorNotYetValid, "token used before issued", nil)
		}
	}
	if notBefore != nil {
		if now.Add(skew).Before(notBefore.UTC()) {
			return newValidationError(ValidationErrorNotYetValid, "token is not yet valid", nil)
		}
	}
	return nil
}

func (v *Validator) validateIssuer(claims map[string]any) *ValidationError {
	claim, _ := claims["iss"].(string)
	if claim == "" {
		return newValidationError(ValidationErrorIssuerMismatch, "issuer claim missing", nil)
	}
	if claim != v.config.Issuer {
		return newValidationError(ValidationErrorIssuerMismatch, "issuer claim mismatch", nil)
	}
	return nil
}

func (v *Validator) validateAudience(claims map[string]any) *ValidationError {
	if len(v.audienceAllowlist) == 0 {
		return nil
	}

	val := claims["aud"]
	if val == nil {
		return newValidationError(ValidationErrorAudienceMismatch, "audience claim missing", nil)
	}

	// Optimized path to avoid allocations in extractAudiences
	switch raw := val.(type) {
	case string:
		if raw == "" {
			return newValidationError(ValidationErrorAudienceMismatch, "audience claim missing", nil)
		}
		if _, ok := v.audienceAllowlist[raw]; ok {
			return nil
		}

	case []any:
		foundValidString := false
		for _, item := range raw {
			if s, ok := item.(string); ok && s != "" {
				foundValidString = true
				if _, ok := v.audienceAllowlist[s]; ok {
					return nil
				}
			}
		}
		if !foundValidString {
			return newValidationError(ValidationErrorAudienceMismatch, "audience claim missing", nil)
		}

	case []string:
		foundValidString := false
		for _, s := range raw {
			if s != "" {
				foundValidString = true
				if _, ok := v.audienceAllowlist[s]; ok {
					return nil
				}
			}
		}
		if !foundValidString {
			return newValidationError(ValidationErrorAudienceMismatch, "audience claim missing", nil)
		}

	default:
		return newValidationError(ValidationErrorAudienceMismatch, "audience claim missing", nil)
	}

	return newValidationError(ValidationErrorAudienceMismatch, "audience claim not allowed", nil)
}

func (v *Validator) validateType(claims map[string]any) *ValidationError {
	if len(v.tokenTypeAllowlist) == 0 {
		return nil
	}
	typ, _ := claims["typ"].(string)
	if typ == "" {
		return newValidationError(ValidationErrorTypeMismatch, "token type claim missing", nil)
	}
	if _, ok := v.tokenTypeAllowlist[strings.ToLower(typ)]; !ok {
		return newValidationError(ValidationErrorTypeMismatch, "token type not allowed", nil)
	}
	return nil
}

func (v *Validator) validateAZP(claims map[string]any) *ValidationError {
	if len(v.azpAllowlist) == 0 {
		return nil
	}
	azp, _ := claims["azp"].(string)
	if azp == "" {
		return newValidationError(ValidationErrorAZPMismatch, "authorized party claim missing", nil)
	}
	if _, ok := v.azpAllowlist[azp]; !ok {
		return newValidationError(ValidationErrorAZPMismatch, "authorized party not allowed", nil)
	}
	return nil
}

func toSet(values []string, lower bool) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if lower {
			set[strings.ToLower(value)] = struct{}{}
		} else {
			set[value] = struct{}{}
		}
	}
	return set
}

func extractAudiences(value any) []string {
	switch v := value.(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []any:
		audiences := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				audiences = append(audiences, s)
			}
		}
		return audiences
	case []string:
		audiences := make([]string, 0, len(v))
		for _, s := range v {
			if s != "" {
				audiences = append(audiences, s)
			}
		}
		return audiences
	default:
		return nil
	}
}

func parseNotBefore(value any) (*time.Time, error) {
	if value == nil {
		return nil, nil
	}
	switch v := value.(type) {
	case float64:
		t := time.Unix(int64(v), 0).UTC()
		return &t, nil
	case int64:
		t := time.Unix(v, 0).UTC()
		return &t, nil
	case json.Number:
		i, err := v.Int64()
		if err != nil {
			return nil, err
		}
		t := time.Unix(i, 0).UTC()
		return &t, nil
	case string:
		if v == "" {
			return nil, nil
		}
		i, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, err
		}
		t := time.Unix(i, 0).UTC()
		return &t, nil
	default:
		return nil, nil
	}
}
