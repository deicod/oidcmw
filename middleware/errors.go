package middleware

type errorCode string

const (
	errorCodeInvalidRequest errorCode = "invalid_request"
	errorCodeInvalidToken   errorCode = "invalid_token"
	errorCodeServerError    errorCode = "server_error"
)

type authError struct {
	code        errorCode
	description string
	status      int
	cause       error
}

func (e authError) Error() string {
	return e.description
}

func (e authError) Unwrap() error {
	return e.cause
}

func newAuthError(code errorCode, status int, description string, err error) authError {
	return authError{code: code, status: status, description: description, cause: err}
}
