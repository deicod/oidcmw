# Quick Start

This guide walks through wiring the middleware into an existing `net/http` service and configuring authentication against an OpenID Connect issuer.

## 1. Install the module

```
go get github.com/deicod/oidcmw
```

## 2. Configure the middleware

Create a `config.Config` value with your issuer information and any claim constraints that must be enforced. The middleware validates signatures and temporal claims automatically.

```go
cfg := config.Config{
        Issuer:            "https://auth.example.com/realms/dev",
        Audiences:         []string{"account"},
        AuthorizedParties: []string{"spa"},
}
```

You can load configuration from files and environment variables using the helpers in the `config` package:

```go
cfg, err := config.Load(config.LoadOptions{
        File:      "./examples/config/quickstart.yaml",
        EnvPrefix: "OIDC",
})
if err != nil {
        log.Fatal(err)
}
```

## 3. Wrap your handlers

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
        if !v.HasRealmRole("default-roles-dev") {
                http.Error(w, "forbidden", http.StatusForbidden)
                return
        }
        w.WriteHeader(http.StatusNoContent)
})))

log.Fatal(http.ListenAndServe(":8080", mux))
```

Downstream handlers can access the validated JWT claims via `middleware.ClaimsFromContext` when custom authorization logic is required.

### Customize the viewer

When services need a different principal abstraction, provide `ViewerFactory` and `ViewerContextBinder` hooks on the configuration. The factory converts validated claims into your type, while the binder stores it on the request context alongside the cloned claims map exposed via `middleware.WithClaims`.

```go
type account struct {
        subject string
        scopes  []string
}

type accountContextKey struct{}

cfg.ViewerFactory = func(claims map[string]any) (any, error) {
        subject, _ := claims["sub"].(string)
        rawScopes, _ := claims["scope"].(string)
        return &account{subject: subject, scopes: strings.Fields(rawScopes)}, nil
}

cfg.ViewerContextBinder = func(ctx context.Context, v any, claims map[string]any) context.Context {
        if acct, ok := v.(*account); ok {
                ctx = context.WithValue(ctx, accountContextKey{}, acct)
        }
        return middleware.WithClaims(ctx, claims)
}
```

Downstream handlers can retrieve the custom type using the context key and still reach for the original claims map when needed.

## 4. Observe authentication outcomes

Enable structured logging, metrics, and tracing by supplying the corresponding hooks on the configuration struct:

```go
registry := prometheus.NewRegistry()
metrics, err := observability.NewMetrics(observability.MetricsOptions{Registerer: registry, Namespace: "oidcmw"})
if err != nil {
        log.Fatal(err)
}

cfg.Logger = slog.New(slog.NewTextHandler(os.Stdout, nil))
cfg.MetricsRecorder = metrics
cfg.Tracer = otel.Tracer("oidcmw")
```

The middleware logs failures, emits Prometheus counters/histograms, and annotates OpenTelemetry spans with issuer, outcome, and error code attributes.

## 5. Test with the fake issuer

The `internal/testutil/issuer` package exposes a `FakeIssuer` that spins up an in-memory discovery and JWKS server for unit tests:

```go
fake := issuer.New(t)
t.Cleanup(fake.Close)

token := fake.SignToken(t, map[string]any{
        "iss": fake.Issuer(),
        "sub": "alice",
        "aud": "account",
        "exp": time.Now().Add(time.Minute).Unix(),
})
```

Use `issuer.SignWithRandomKey` to create tokens signed by unknown keys when exercising negative paths.
