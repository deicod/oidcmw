package tokensource

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ErrNotFound indicates that a token could not be located by a Source.
var ErrNotFound = errors.New("oidcmw: bearer token not found")

// Source extracts a bearer token from an incoming HTTP request.
type Source interface {
	Extract(*http.Request) (string, error)
}

// SourceFunc allows ordinary functions to act as token sources.
type SourceFunc func(*http.Request) (string, error)

// Extract implements the Source interface.
func (f SourceFunc) Extract(r *http.Request) (string, error) {
	return f(r)
}

// Type identifies the built-in token source implementations.
type Type string

const (
	// TypeAuthorizationHeader reads tokens from the Authorization header using the Bearer scheme.
	TypeAuthorizationHeader Type = "authorization_header"
	// TypeHeader reads tokens from a custom header without performing scheme validation.
	TypeHeader Type = "header"
	// TypeCookie reads tokens from an HTTP cookie.
	TypeCookie Type = "cookie"
	// TypeQuery reads tokens from a query string parameter.
	TypeQuery Type = "query"
	// TypeWebSocketProtocol reads tokens from the Sec-WebSocket-Protocol header.
	TypeWebSocketProtocol Type = "websocket_protocol"
)

// Definition declares a token source constructed via configuration.
type Definition struct {
	Type   Type   `json:"type" yaml:"type"`
	Name   string `json:"name" yaml:"name"`
	Scheme string `json:"scheme" yaml:"scheme"`
}

// Build materializes the configured token source.
func (d Definition) Build() (Source, error) {
	switch d.Type {
	case TypeAuthorizationHeader:
		scheme := strings.TrimSpace(d.Scheme)
		if scheme == "" {
			return AuthorizationHeader(), nil
		}
		return AuthorizationHeaderWithScheme(scheme), nil
	case TypeHeader:
		name := strings.TrimSpace(d.Name)
		if name == "" {
			return nil, fmt.Errorf("tokensource: header token source requires a name")
		}
		scheme := strings.TrimSpace(d.Scheme)
		if scheme == "" {
			return Header(name), nil
		}
		return HeaderWithScheme(name, scheme), nil
	case TypeCookie:
		name := strings.TrimSpace(d.Name)
		if name == "" {
			return nil, fmt.Errorf("tokensource: cookie token source requires a name")
		}
		return Cookie(name), nil
	case TypeQuery:
		name := strings.TrimSpace(d.Name)
		if name == "" {
			return nil, fmt.Errorf("tokensource: query token source requires a name")
		}
		return Query(name), nil
	case TypeWebSocketProtocol:
		scheme := strings.TrimSpace(d.Scheme)
		return WebSocketProtocolWithScheme(scheme), nil
	default:
		return nil, fmt.Errorf("tokensource: unsupported token source type %q", d.Type)
	}
}

// AuthorizationHeader extracts tokens from the Authorization header using the Bearer scheme.
func AuthorizationHeader() Source {
	return AuthorizationHeaderWithScheme("Bearer")
}

// AuthorizationHeaderWithScheme extracts tokens from the Authorization header using a custom scheme.
func AuthorizationHeaderWithScheme(scheme string) Source {
	normalized := strings.TrimSpace(scheme)
	return SourceFunc(func(r *http.Request) (string, error) {
		header := r.Header.Get("Authorization")
		if header == "" {
			return "", ErrNotFound
		}

		if normalized == "" {
			token := strings.TrimSpace(header)
			if token == "" {
				return "", ErrNotFound
			}
			return token, nil
		}

		if len(header) <= len(normalized) {
			return "", ErrNotFound
		}
		if header[len(normalized)] != ' ' {
			return "", ErrNotFound
		}
		if !strings.EqualFold(header[:len(normalized)], normalized) {
			return "", ErrNotFound
		}

		token := strings.TrimSpace(header[len(normalized)+1:])
		if token == "" {
			return "", ErrNotFound
		}
		return token, nil
	})
}

// Header extracts tokens from an arbitrary HTTP header without checking a scheme prefix.
func Header(name string) Source {
	return SourceFunc(func(r *http.Request) (string, error) {
		value := r.Header.Get(name)
		if strings.TrimSpace(value) == "" {
			return "", ErrNotFound
		}
		return strings.TrimSpace(value), nil
	})
}

// HeaderWithScheme extracts tokens from a header requiring the supplied scheme prefix.
func HeaderWithScheme(name, scheme string) Source {
	normalized := strings.TrimSpace(scheme)
	return SourceFunc(func(r *http.Request) (string, error) {
		value := r.Header.Get(name)
		if value == "" {
			return "", ErrNotFound
		}
		if normalized == "" {
			token := strings.TrimSpace(value)
			if token == "" {
				return "", ErrNotFound
			}
			return token, nil
		}
		if len(value) <= len(normalized) {
			return "", ErrNotFound
		}
		if value[len(normalized)] != ' ' {
			return "", ErrNotFound
		}
		if !strings.EqualFold(value[:len(normalized)], normalized) {
			return "", ErrNotFound
		}
		token := strings.TrimSpace(value[len(normalized)+1:])
		if token == "" {
			return "", ErrNotFound
		}
		return token, nil
	})
}

// Cookie extracts tokens from the provided cookie name.
func Cookie(name string) Source {
	return SourceFunc(func(r *http.Request) (string, error) {
		c, err := r.Cookie(name)
		if err != nil {
			if errors.Is(err, http.ErrNoCookie) {
				return "", ErrNotFound
			}
			return "", err
		}
		if strings.TrimSpace(c.Value) == "" {
			return "", ErrNotFound
		}
		return strings.TrimSpace(c.Value), nil
	})
}

// Query extracts tokens from a query string parameter.
func Query(name string) Source {
	return SourceFunc(func(r *http.Request) (string, error) {
		if r.URL == nil {
			return "", ErrNotFound
		}
		value := r.URL.Query().Get(name)
		if strings.TrimSpace(value) == "" {
			return "", ErrNotFound
		}
		return strings.TrimSpace(value), nil
	})
}

// WebSocketProtocol extracts tokens from the Sec-WebSocket-Protocol header using the default scheme sentinel.
func WebSocketProtocol() Source {
	return WebSocketProtocolWithScheme("")
}

// WebSocketProtocolWithScheme extracts the token that follows the provided scheme sentinel within the Sec-WebSocket-Protocol header.
// The header is interpreted as an ordered, comma-separated list. When the sentinel is omitted or empty, "bearer" is used.
func WebSocketProtocolWithScheme(scheme string) Source {
	normalized := strings.TrimSpace(scheme)
	if normalized == "" {
		normalized = "bearer"
	}
	return SourceFunc(func(r *http.Request) (string, error) {
		values := r.Header.Values("Sec-WebSocket-Protocol")
		if len(values) == 0 {
			return "", ErrNotFound
		}

		var entries []string
		for _, raw := range values {
			for _, part := range strings.Split(raw, ",") {
				trimmed := strings.TrimSpace(part)
				if trimmed == "" {
					continue
				}
				entries = append(entries, trimmed)
			}
		}

		for i := 0; i < len(entries); i++ {
			if strings.EqualFold(entries[i], normalized) {
				if i+1 >= len(entries) {
					return "", ErrNotFound
				}
				token := strings.TrimSpace(entries[i+1])
				if token == "" {
					return "", ErrNotFound
				}
				return token, nil
			}
		}

		return "", ErrNotFound
	})
}

// ParseList converts a comma separated list of token source descriptors to Definition values.
// Supported descriptor formats:
//   - "authorization_header"
//   - "header:<name>" or "header:<name>:<scheme>"
//   - "cookie:<name>"
//   - "query:<name>"
//   - "websocket_protocol" or "websocket_protocol:<scheme>"
func ParseList(raw string) ([]Definition, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	defs := make([]Definition, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		def, err := parseDescriptor(part)
		if err != nil {
			return nil, err
		}
		defs = append(defs, def)
	}
	return defs, nil
}

func parseDescriptor(descriptor string) (Definition, error) {
	descriptor = strings.TrimSpace(descriptor)
	lower := strings.ToLower(descriptor)
	switch {
	case lower == string(TypeAuthorizationHeader):
		return Definition{Type: TypeAuthorizationHeader}, nil
	case strings.HasPrefix(lower, string(TypeHeader)+":"):
		payload := strings.SplitN(descriptor[len(TypeHeader)+1:], ":", 2)
		name := strings.TrimSpace(payload[0])
		if name == "" {
			return Definition{}, fmt.Errorf("tokensource: header token descriptor missing name")
		}
		if len(payload) == 2 {
			scheme, err := url.QueryUnescape(strings.TrimSpace(payload[1]))
			if err != nil {
				return Definition{}, fmt.Errorf("tokensource: invalid header scheme: %w", err)
			}
			return Definition{Type: TypeHeader, Name: name, Scheme: scheme}, nil
		}
		return Definition{Type: TypeHeader, Name: name}, nil
	case strings.HasPrefix(lower, string(TypeCookie)+":"):
		name := strings.TrimSpace(descriptor[len(TypeCookie)+1:])
		if name == "" {
			return Definition{}, fmt.Errorf("tokensource: cookie token descriptor missing name")
		}
		return Definition{Type: TypeCookie, Name: name}, nil
	case strings.HasPrefix(lower, string(TypeQuery)+":"):
		name := strings.TrimSpace(descriptor[len(TypeQuery)+1:])
		if name == "" {
			return Definition{}, fmt.Errorf("tokensource: query token descriptor missing name")
		}
		return Definition{Type: TypeQuery, Name: name}, nil
	case lower == string(TypeWebSocketProtocol):
		return Definition{Type: TypeWebSocketProtocol}, nil
	case strings.HasPrefix(lower, string(TypeWebSocketProtocol)+":"):
		scheme, err := url.QueryUnescape(strings.TrimSpace(descriptor[len(TypeWebSocketProtocol)+1:]))
		if err != nil {
			return Definition{}, fmt.Errorf("tokensource: invalid websocket protocol scheme: %w", err)
		}
		if strings.TrimSpace(scheme) == "" {
			return Definition{}, fmt.Errorf("tokensource: websocket protocol descriptor missing scheme")
		}
		return Definition{Type: TypeWebSocketProtocol, Scheme: scheme}, nil
	default:
		return Definition{}, fmt.Errorf("tokensource: unsupported token descriptor %q", descriptor)
	}
}
