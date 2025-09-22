package issuer

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

type option func(*FakeIssuer)

// WithSigningKey configures the fake issuer to use the provided key and key ID.
func WithSigningKey(key *rsa.PrivateKey, keyID string) option {
	return func(fi *FakeIssuer) {
		fi.key = key
		fi.keyID = keyID
	}
}

// FakeIssuer hosts a minimal OpenID Connect discovery and JWKS server backed by an RSA keypair.
type FakeIssuer struct {
	key    *rsa.PrivateKey
	keyID  string
	server *httptest.Server
	issuer string
	jwks   []byte
}

// New creates a FakeIssuer. Callers must invoke Close when finished.
func New(tb testing.TB, opts ...option) *FakeIssuer {
	tb.Helper()

	fi := &FakeIssuer{keyID: "test-key"}
	for _, opt := range opts {
		if opt != nil {
			opt(fi)
		}
	}
	if fi.key == nil {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			tb.Fatalf("generate rsa key: %v", err)
		}
		fi.key = key
	}
	if fi.keyID == "" {
		fi.keyID = "test-key"
	}

	fi.jwks = buildJWKS(tb, fi.key, fi.keyID)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]any{
			"issuer":                 fi.issuer,
			"jwks_uri":               fi.issuer + "/jwks",
			"token_endpoint":         fi.issuer + "/token",
			"authorization_endpoint": fi.issuer + "/auth",
		}
		_ = json.NewEncoder(w).Encode(response)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fi.jwks)
	})

	server := httptest.NewServer(mux)
	fi.server = server
	fi.issuer = server.URL

	return fi
}

// Issuer returns the base issuer URL exposed by the fake server.
func (fi *FakeIssuer) Issuer() string {
	if fi == nil {
		return ""
	}
	return fi.issuer
}

// JWKSURL returns the JWKS endpoint served by the fake issuer.
func (fi *FakeIssuer) JWKSURL() string {
	if fi == nil {
		return ""
	}
	return fi.issuer + "/jwks"
}

// SignToken signs the provided claims using the issuer's key and returns a compact JWT.
func (fi *FakeIssuer) SignToken(tb testing.TB, claims map[string]any) string {
	tb.Helper()
	if fi == nil {
		tb.Fatalf("SignToken called on nil FakeIssuer")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	token.Header["kid"] = fi.keyID
	signed, err := token.SignedString(fi.key)
	if err != nil {
		tb.Fatalf("sign token: %v", err)
	}
	return signed
}

// Close shuts down the HTTP server backing the fake issuer.
func (fi *FakeIssuer) Close() {
	if fi == nil {
		return
	}
	if fi.server != nil {
		fi.server.Close()
	}
}

// SignWithRandomKey produces a JWT signed by a fresh RSA key unrelated to the fake issuer.
func SignWithRandomKey(tb testing.TB, claims map[string]any) string {
	tb.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("generate rsa key: %v", err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	token.Header["kid"] = "other"
	signed, err := token.SignedString(key)
	if err != nil {
		tb.Fatalf("sign token: %v", err)
	}
	return signed
}

func buildJWKS(tb testing.TB, key *rsa.PrivateKey, keyID string) []byte {
	tb.Helper()
	n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())

	jwk := map[string]any{
		"kty": "RSA",
		"alg": "RS256",
		"use": "sig",
		"kid": keyID,
		"n":   n,
		"e":   e,
	}

	body, err := json.Marshal(map[string]any{"keys": []any{jwk}})
	if err != nil {
		tb.Fatalf("marshal jwks: %v", err)
	}
	return body
}
