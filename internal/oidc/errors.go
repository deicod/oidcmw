package oidc

type ValidationErrorCode string

const (
	ValidationErrorInvalidToken     ValidationErrorCode = "invalid_token"
	ValidationErrorExpired          ValidationErrorCode = "expired_token"
	ValidationErrorNotYetValid      ValidationErrorCode = "not_yet_valid"
	ValidationErrorClaimMismatch    ValidationErrorCode = "claim_mismatch"
	ValidationErrorMalformedToken   ValidationErrorCode = "malformed_token"
	ValidationErrorIssuerMismatch   ValidationErrorCode = "issuer_mismatch"
	ValidationErrorAudienceMismatch ValidationErrorCode = "audience_mismatch"
	ValidationErrorTypeMismatch     ValidationErrorCode = "type_mismatch"
	ValidationErrorAZPMismatch      ValidationErrorCode = "authorized_party_mismatch"
)

type ValidationError struct {
	Code        ValidationErrorCode
	Description string
	Err         error
}

func (e *ValidationError) Error() string {
	if e.Description != "" {
		return e.Description
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return string(e.Code)
}

func (e *ValidationError) Unwrap() error {
	return e.Err
}

func newValidationError(code ValidationErrorCode, description string, err error) *ValidationError {
	return &ValidationError{Code: code, Description: description, Err: err}
}
