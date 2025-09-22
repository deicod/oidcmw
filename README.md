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

The `internal/testutil/issuer` package spins up a fake discovery server with a JWKS endpoint and exposes helpers for signing JWTs. Use `issuer.New(t)` in unit tests to obtain an issuer URL and `issuer.SignWithRandomKey` to craft invalid tokens for negative scenarios.
