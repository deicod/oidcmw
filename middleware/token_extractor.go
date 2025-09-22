package middleware

import (
	"errors"
	"net/http"
	"strings"
)

var errNoTokenFound = errors.New("oidcmw: bearer token not found")

// tokenExtractor extracts a bearer token from an HTTP request.
type tokenExtractor interface {
	Extract(*http.Request) (string, error)
}

// authorizationHeaderExtractor reads tokens from the Authorization header.
type authorizationHeaderExtractor struct{}

func (authorizationHeaderExtractor) Extract(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", errNoTokenFound
	}
	if !strings.HasPrefix(strings.ToLower(header), "bearer ") {
		return "", errNoTokenFound
	}
	token := strings.TrimSpace(header[len("Bearer "):])
	if token == "" {
		return "", errNoTokenFound
	}
	return token, nil
}

func defaultExtractors() []tokenExtractor {
	return []tokenExtractor{authorizationHeaderExtractor{}}
}
