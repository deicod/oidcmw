package oidc

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/deicod/oidcmw/config"
)

func TestNewValidatorUsesConfiguredHTTPClient(t *testing.T) {
	issuer := "https://issuer.invalid"
	transport := &stubTransport{t: t}
	client := &http.Client{Transport: transport}

	cfg := config.Config{
		Issuer:     issuer,
		HTTPClient: client,
	}
	cfg.SetDefaults()

	if _, err := NewValidator(context.Background(), cfg); err != nil {
		t.Fatalf("NewValidator returned error: %v", err)
	}

	if !transport.sawPath("/.well-known/openid-configuration") {
		t.Fatalf("expected discovery request to use configured client; got paths: %v", transport.paths())
	}
}

type stubTransport struct {
	t    *testing.T
	mu   sync.Mutex
	seen []string
}

func (s *stubTransport) sawPath(path string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.seen {
		if p == path {
			return true
		}
	}
	return false
}

func (s *stubTransport) paths() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.seen))
	copy(out, s.seen)
	return out
}

func (s *stubTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	s.mu.Lock()
	s.seen = append(s.seen, req.URL.Path)
	s.mu.Unlock()

	switch req.URL.Path {
	case "/.well-known/openid-configuration":
		body := `{"issuer":"` + req.URL.Scheme + "://" + req.URL.Host + `","jwks_uri":"` + req.URL.Scheme + "://" + req.URL.Host + `/keys"}`
		return s.response(body), nil
	case "/keys":
		return s.response(`{"keys":[]}`), nil
	default:
		s.t.Fatalf("unexpected request path: %s", req.URL.String())
		return nil, nil
	}
}

func (s *stubTransport) response(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}
