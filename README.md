# oidcmw

`oidcmw` provides production-focused OpenID Connect middleware for Go's `net/http` stack.

```go
package main

import (
        "log"
        "net/http"

        "github.com/deicod/oidcmw/config"
        "github.com/deicod/oidcmw/middleware"
        "github.com/deicod/oidcmw/viewer"
)

func main() {
        cfg := config.Config{
                Issuer:            "https://auth.icod.de/realms/dev",
                Audiences:         []string{"account"},
                AuthorizedParties: []string{"spa"},
        }

        mw, err := middleware.NewMiddleware(cfg)
        if err != nil {
                log.Fatalf("middleware setup failed: %v", err)
        }

        mux := http.NewServeMux()
        mux.Handle("/protected", mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                v, err := viewer.FromContext(r.Context())
                if err != nil {
                        http.Error(w, "unauthorized", http.StatusUnauthorized)
                        return
                }
                if !v.HasRealmRole("default-roles-dev") {
                        http.Error(w, "forbidden", http.StatusForbidden)
                        return
                }
                w.WriteHeader(http.StatusNoContent)
        })))

        log.Fatal(http.ListenAndServe(":8080", mux))
}
```

Downstream handlers can also inspect the original JWT claims via `middleware.ClaimsFromContext` when custom authorization logic is required.

## Customizing the principal

Packages that prefer a different identity type can replace the default `viewer.Viewer` by supplying hooks on `config.Config`:

```go
type account struct {
        subject string
        email   string
}

type accountContextKey struct{}

cfg := config.Config{
        Issuer:            "https://auth.icod.de/realms/dev",
        Audiences:         []string{"account"},
        AuthorizedParties: []string{"spa"},
        ViewerFactory: func(claims map[string]any) (any, error) {
                subject, _ := claims["sub"].(string)
                email, _ := claims["email"].(string)
                return &account{subject: subject, email: email}, nil
        },
        ViewerContextBinder: func(ctx context.Context, v any, claims map[string]any) context.Context {
                if acct, ok := v.(*account); ok {
                        ctx = context.WithValue(ctx, accountContextKey{}, acct)
                }
                return middleware.WithClaims(ctx, claims)
        },
}
```

The middleware invokes `ViewerFactory` after verifying the token. Whatever value it returns is passed to `ViewerContextBinder`, which can attach the principal to the context alongside the cloned claims map via `middleware.WithClaims`. The default implementation continues to expose `viewer.FromContext` helpers, so existing integrations keep working without additional configuration.

## Optional Authentication

Set `config.Config.AllowAnonymousRequests` to `true` to let requests without a bearer token reach your handlers. When a token is
present the middleware still validates it and enriches the context with a viewer. Downstream code can differentiate anonymous
callers from authenticated users by invoking `viewer.IsAuthenticated`.

```go
cfg := config.Config{
        Issuer:                 "https://auth.icod.de/realms/dev",
        AllowAnonymousRequests: true,
}

handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if !viewer.IsAuthenticated(r.Context()) {
                w.WriteHeader(http.StatusOK)
                return
        }
        v, _ := viewer.FromContext(r.Context())
        fmt.Fprintf(w, "hello %s", v.PreferredUsername)
}))
```

## Error Responses

Authentication failures return RFC 6750 inspired payloads. When the middleware responds with `401 Unauthorized` it also includes a `WWW-Authenticate` header that repeats the `error` and `error_description` values (for example `Bearer error="invalid_token", error_description="token validation failed"`). Header values are safely escaped so integrators can rely on them for programmatic handling or surfacing messages to clients.

## Documentation

- [Quick Start](docs/quickstart.md)
- [Troubleshooting](docs/troubleshooting.md)
- [FAQ](docs/faq.md)

The documentation set covers configuration loaders, observability hooks, and guidance for operating the middleware in production.

## Configuration

The `config` package ships with helpers for loading middleware configuration from files and environment variables. The loader composes values in the following order:

1. Start from a programmatic `config.Config` value (useful for defaults).
2. Merge values from a JSON or YAML file via `config.Load`.
3. Override with environment variables using a configurable prefix.

```go
cfg, err := config.Load(config.LoadOptions{
        Base: config.Config{Audiences: []string{"account"}},
        File: "./examples/config/quickstart.yaml",
        EnvPrefix: "OIDC",
})
if err != nil {
        log.Fatal(err)
}
```

Environment variables support comma-delimited lists for `AUDIENCES`, `TOKEN_TYPES`, and `AUTHORIZED_PARTIES`. Token extraction can be customized by specifying `TOKEN_SOURCES`, e.g. `cookie:session,authorization_header`. Built-in token sources include authorization headers, custom headers, cookies, and query parameters.

## Observability

`config.Config` exposes optional hooks for structured logging, metrics, and tracing. By default middleware events are logged via Go's `log/slog` package. To publish Prometheus metrics, supply a recorder implementation such as the helper from the `observability` package:

```go
registry := prometheus.NewRegistry()
metrics, err := observability.NewMetrics(observability.MetricsOptions{Registerer: registry, Namespace: "oidcmw"})
if err != nil {
        log.Fatal(err)
}

cfg := config.Config{
        Issuer:          "https://auth.icod.de/realms/dev",
        Audiences:       []string{"account"},
        MetricsRecorder: metrics,
        Tracer:          otel.GetTracerProvider().Tracer("oidcmw"),
}
```

When configured, middleware automatically records authentication outcomes, latency, and OpenTelemetry span attributes including issuer, outcome, and error codes.

## Testing Utilities

The `testutil/issuer` package spins up a fake discovery server with a JWKS endpoint and exposes helpers for signing JWTs. Use `issuer.New(t)` in unit tests to obtain an issuer URL and `issuer.SignWithRandomKey` to craft invalid tokens for negative scenarios.
