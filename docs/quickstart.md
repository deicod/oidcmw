# Quick Start

This guide walks through integrating `oidcmw` with a simple `net/http` application.

## Prerequisites

- Go 1.22 or newer.
- An OpenID Connect provider (Keycloak, Okta, Auth0, etc.).
- Client credentials issued by the provider with an audience that matches your API.

## Install the Module

```bash
go get github.com/deicod/oidcmw
```

## Configure the Middleware

Populate a configuration struct or load one from disk using the helpers in the `config` package. The example below shows configuration driven by YAML with environment variable overrides:

```go
cfg, err := config.Load(config.LoadOptions{
        File:      "./config/oidc.yaml",
        EnvPrefix: "OIDC",
})
if err != nil {
        log.Fatalf("load config: %v", err)
}
```

A minimal configuration contains the issuer URL and either audiences or authorized parties:

```yaml
issuer: https://auth.example.com/realms/demo
audiences:
  - account
authorized_parties:
  - spa
```

## Protect Handlers

Wrap your handlers with `middleware.NewMiddleware`. Validated requests include a `viewer.Viewer` in the request context for downstream authorization decisions.

```go
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
        if !v.HasRealmRole("default-roles-demo") {
                http.Error(w, "forbidden", http.StatusForbidden)
                return
        }
        w.Write([]byte("ok"))
})))
```

## Observability Hooks

Provide a Prometheus registerer and OpenTelemetry tracer to collect metrics and traces:

```go
registry := prometheus.NewRegistry()
metrics, err := observability.NewMetrics(observability.MetricsOptions{Registerer: registry, Namespace: "oidcmw"})
if err != nil {
        log.Fatalf("metrics: %v", err)
}

cfg.MetricsRecorder = metrics
cfg.Tracer = otel.GetTracerProvider().Tracer("auth")
```

Errors are logged with `log/slog` by default. Supply a custom logger through `config.Config.Logger` to integrate with your logging pipeline.

## Verify Locally

Use the `testutil` package to emulate an issuer during development or when writing unit tests. See [Testing Helpers](testing.md) for details.

Run the full validation suite before committing changes:

```bash
go test ./...
go vet ./...
staticcheck ./...
```
