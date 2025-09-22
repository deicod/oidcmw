# Troubleshooting

A few quick checks can help diagnose most authentication issues when integrating the middleware.

## Invalid or Missing Tokens

* **Symptom:** Requests are rejected with `401` and error code `invalid_request`.
* **Resolution:** Ensure the client sends an `Authorization: Bearer <token>` header or configure additional token sources via `config.Config.TokenSources`.
* **Observation:** Enable debug logging on your application logger to confirm which token source returned `ErrNotFound`.

## Signature Verification Failures

* **Symptom:** Responses contain `error="invalid_token"` immediately after startup.
* **Resolution:** Verify that the issuer configuration matches the realm that minted the token and that the JWKS endpoint is reachable. The middleware logs the wrapped validation error to aid debugging.
* **Observation:** Use the fake issuer test utility to reproduce failures locally by calling `issuer.SignWithRandomKey`.

## Claim Mismatches

* **Symptom:** Tokens validate initially but are rejected when claim restrictions are tightened.
* **Resolution:** Inspect the token payload using `middleware.ClaimsFromContext` or the viewer helpers to confirm `aud`, `azp`, and `typ` values. Update `config.Config` allow-lists as needed.

## Clock Skew Issues

* **Symptom:** Tokens appear to expire immediately with `not_yet_valid` errors.
* **Resolution:** Increase `config.Config.ClockSkew` to accommodate issuer/service clock drift. The default skew is 30 seconds.

## JWKS Fetch Failures

* **Symptom:** Requests fail with server errors after network blips.
* **Resolution:** Provide a custom `http.Client` on the configuration with appropriate timeouts and retry behavior. The validator falls back to cached keys when possible, but persistent failures require manual intervention.

## Metrics or Tracing Not Emitted

* **Symptom:** Prometheus counters remain at zero or traces lack spans.
* **Resolution:** Confirm that `config.Config.MetricsRecorder` and `config.Config.Tracer` are set. When using the helper from the `observability` package, ensure collectors are registered with the same registry scraped by Prometheus.

## Staticcheck Complains About Go Version

* **Symptom:** CI logs include `requires newer Go version` errors.
* **Resolution:** The module targets Go 1.24.3. Set `GOTOOLCHAIN=go1.24.3` locally or install Go 1.24.3 so that `go test`, `go vet`, and `staticcheck` pick up the correct toolchain.
