# Testing Helpers

The `testutil` package ships with utilities for exercising the middleware without relying on an external identity provider.

## Spin Up a Fake Issuer

```go
issuer := testutil.NewIssuer(t)
cfg := config.Config{Issuer: issuer.URL(), Audiences: []string{"account"}}

mw, err := middleware.NewMiddleware(cfg)
require.NoError(t, err)
```

`NewIssuer` starts an `httptest.Server` that exposes discovery and JWKS endpoints. The server is closed automatically when the test finishes.

## Issue Tokens

Call `issuer.SignToken` to mint RS256-signed JWTs:

```go
now := time.Now().Add(-time.Minute)
token := issuer.SignToken(map[string]any{
        "iss": issuer.URL(),
        "sub": "subject",
        "aud": "account",
        "exp": now.Add(time.Minute).Unix(),
        "iat": now.Unix(),
})
```

For negative tests, use `testutil.SignTokenWithKey` together with `testutil.GenerateRSAKey` to craft tokens signed by alternative keys.

## Customize Keys

`NewIssuer` accepts options that control the generated signing key:

```go
issuer := testutil.NewIssuer(t,
        testutil.WithKeyID("kid-1"),
        testutil.WithKeyBits(3072),
)
```

Provide a pre-generated key with `testutil.WithSigningKey` when deterministic key material is required.

## Fetch JWKS

The JWKS endpoint is available at `issuer.URL() + "/jwks"`, making it easy to feed the signing keys into other systems or snapshot them for contract tests.
