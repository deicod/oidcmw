package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// Issuer represents an in-memory OpenID Connect provider suitable for tests.
type Issuer struct {
	tb     testing.TB
	server *httptest.Server
	key    *rsa.PrivateKey
	keyID  string
	jwks   []byte
}

// IssuerOption configures Issuer construction.
type IssuerOption func(*issuerConfig)

type issuerConfig struct {
	Key     *rsa.PrivateKey
	KeyID   string
	KeyBits int
}

// WithSigningKey supplies a pre-generated RSA private key for the issuer.
func WithSigningKey(key *rsa.PrivateKey) IssuerOption {
	return func(cfg *issuerConfig) {
		cfg.Key = key
	}
}

// WithKeyID overrides the key identifier exposed in the JWKS document.
func WithKeyID(keyID string) IssuerOption {
	return func(cfg *issuerConfig) {
		cfg.KeyID = keyID
	}
}

// WithKeyBits customizes the RSA key size when a key is generated automatically.
func WithKeyBits(bits int) IssuerOption {
	return func(cfg *issuerConfig) {
		cfg.KeyBits = bits
	}
}

// NewIssuer spins up an HTTP server that mimics an OpenID Connect provider for tests.
// The returned Issuer automatically registers a cleanup handler on tb.
func NewIssuer(tb testing.TB, opts ...IssuerOption) *Issuer {
	tb.Helper()

	cfg := issuerConfig{
		KeyBits: 2048,
		KeyID:   "test-key",
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	key := cfg.Key
	if key == nil {
		var err error
		key, err = rsa.GenerateKey(rand.Reader, cfg.KeyBits)
		if err != nil {
			tb.Fatalf("testutil: generate RSA key: %v", err)
		}
	}

	iss := &Issuer{tb: tb, key: key, keyID: cfg.KeyID}
	jwks, err := buildJWKS(key, cfg.KeyID)
	if err != nil {
		tb.Fatalf("testutil: build JWKS: %v", err)
	}
	iss.jwks = jwks

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]any{
			"issuer":                 iss.URL(),
			"jwks_uri":               iss.URL() + "/jwks",
			"token_endpoint":         iss.URL() + "/token",
			"authorization_endpoint": iss.URL() + "/auth",
		}
		_ = json.NewEncoder(w).Encode(response)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(iss.jwks)
	})

	server := httptest.NewServer(mux)
	iss.server = server
	tb.Cleanup(iss.Close)

	return iss
}

// URL returns the issuer base URL.
func (i *Issuer) URL() string {
	if i == nil || i.server == nil {
		return ""
	}
	return i.server.URL
}

// SignToken signs the provided claims and returns a compact JWT string.
func (i *Issuer) SignToken(claims map[string]any) string {
	i.tb.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	if i.keyID != "" {
		token.Header["kid"] = i.keyID
	}
	signed, err := token.SignedString(i.key)
	if err != nil {
		i.tb.Fatalf("testutil: sign token: %v", err)
	}
	return signed
}

// Close shuts down the underlying HTTP server.
func (i *Issuer) Close() {
	if i == nil || i.server == nil {
		return
	}
	i.server.Close()
	i.server = nil
}

// SigningKey returns the issuer's RSA private key.
func (i *Issuer) SigningKey() *rsa.PrivateKey {
	if i == nil {
		return nil
	}
	return i.key
}

// KeyID returns the identifier attached to the signing key.
func (i *Issuer) KeyID() string {
	if i == nil {
		return ""
	}
	return i.keyID
}

// GenerateRSAKey creates an RSA private key with the provided size.
func GenerateRSAKey(tb testing.TB, bits int) *rsa.PrivateKey {
	tb.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		tb.Fatalf("testutil: generate RSA key: %v", err)
	}
	return key
}

// SignTokenWithKey signs the claims using the provided key and key identifier.
func SignTokenWithKey(tb testing.TB, key *rsa.PrivateKey, keyID string, claims map[string]any) string {
	tb.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	if keyID != "" {
		token.Header["kid"] = keyID
	}
	signed, err := token.SignedString(key)
	if err != nil {
		tb.Fatalf("testutil: sign token with key: %v", err)
	}
	return signed
}

func buildJWKS(key *rsa.PrivateKey, keyID string) ([]byte, error) {
	if key == nil {
		return nil, errors.New("testutil: RSA key is nil")
	}
	modulus := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
	exponent := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
	jwk := map[string]any{
		"kty": "RSA",
		"alg": "RS256",
		"use": "sig",
		"kid": keyID,
		"n":   modulus,
		"e":   exponent,
	}
	body, err := json.Marshal(map[string]any{"keys": []any{jwk}})
	if err != nil {
		return nil, err
	}
	return body, nil
}
