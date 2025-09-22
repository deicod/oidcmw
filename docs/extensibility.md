# Extensibility Guide

`oidcmw` is designed to adapt to a variety of deployment topologies. The middleware can be extended without forking by wiring the following hooks.

## Token Sources

Tokens are extracted via `tokensource.Source` implementations. Compose built-in sources or provide your own:

```go
cfg.TokenSources = []tokensource.Source{
        tokensource.Cookie("session"),
        tokensource.AuthorizationHeader(),
        tokensource.HeaderWithScheme("X-Auth", "Bearer"),
}
```

Configuration files accept descriptors such as `"cookie:session"` or `"header:X-Auth:Bearer"`. Write custom sources with `tokensource.SourceFunc`.

## Custom Claim Validation

Attach additional claim validation logic through `config.Config.ClaimsValidators`:

```go
cfg.ClaimsValidators = []config.ClaimsValidator{
        func(ctx context.Context, claims map[string]any) error {
                if claims["acr"] != "2" {
                        return fmt.Errorf("acr level insufficient")
                }
                return nil
        },
}
```

Return a `*oidc.ValidationError` to control the HTTP response code precisely.

## Error Responses

Override `config.Config.ErrorResponseBuilder` to customize the error payload returned to callers. The builder receives the RFC 6750 error code and a human-readable description.

## HTTP Clients and MTLS

Inject a custom `http.Client` via `config.Config.HTTPClient` to tune timeouts, TLS settings, or retries. Combine with Go's `http.Transport` to support mutual TLS or proxy routing:

```go
cfg.HTTPClient = &http.Client{
        Timeout: 5 * time.Second,
        Transport: &http.Transport{
                TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13},
        },
}
```

## Metrics and Tracing

Supply a metrics recorder and tracer to integrate with your observability stack. The `observability` package exposes a Prometheus-friendly implementation, while any `trace.Tracer` from OpenTelemetry can be used for distributed tracing.
