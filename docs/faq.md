# FAQ

## Which Go version is required?

The module specifies Go 1.24 and includes a toolchain directive that downloads Go 1.24.3 automatically when necessary. Ensure your local environment can fetch that toolchain when running `go test`.

## Can I disable specific claim checks?

Yes. Leave `Audiences`, `TokenTypes`, or `AuthorizedParties` empty to accept all values. Otherwise populate them with the allowed entries.

## How do I validate custom claims?

Provide `config.ClaimsValidator` functions via `config.Config.ClaimsValidators`. They receive the decoded claim map and can return either a custom error or an `*oidc.ValidationError` for fine-grained error codes.

## Can tokens come from cookies or custom headers?

Absolutely. Use `tokensource.Cookie("session")`, `tokensource.Header("X-Auth")`, or combine multiple sources via `config.Config.TokenSources`.

## Where do I find test helpers?

The `internal/testutil/issuer` package exposes a `FakeIssuer` server, JWT signing helpers, and JWKS responses for unit tests.

## Does the middleware support tracing and metrics?

Yes. Supply a `MetricsRecorder` implementation (e.g., `observability.NewMetrics`) and an OpenTelemetry `trace.Tracer` to capture spans and Prometheus-friendly metrics.
