# FAQ

## Which Go version is required?

The module specifies Go 1.24 and includes a toolchain directive that downloads Go 1.24.3 automatically when necessary. Ensure your local environment can fetch that toolchain when running `go test`.

## Can I disable specific claim checks?

Yes. Leave `Audiences`, `TokenTypes`, or `AuthorizedParties` empty to accept all values. Otherwise populate them with the allowed entries.

## How do I validate custom claims?

Provide `config.ClaimsValidator` functions via `config.Config.ClaimsValidators`. They receive the decoded claim map and can return either a custom error or an `*oidc.ValidationError` for fine-grained error codes.

## Can tokens come from cookies or custom headers?

Absolutely. Use `tokensource.Cookie("session")`, `tokensource.Header("X-Auth")`, or combine multiple sources via `config.Config.TokenSources`.

## How do I read tokens during WebSocket upgrades?

Use the `websocket_protocol` token source to inspect the ordered `Sec-WebSocket-Protocol` header entries. The helper treats
`bearer` as the default sentinel and returns the value that follows it (e.g., a JWT). When you use a WebSocket library, make
sure to echo the selected subprotocol in the upgrade response so browsers accept the handshake:

```go
import (
        "net/http"

        "github.com/deicod/oidcmw/tokensource"
        "github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
        Subprotocols: []string{"bearer"},
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
        token, err := tokensource.WebSocketProtocol().Extract(r)
        if err != nil {
                http.Error(w, "missing bearer token", http.StatusUnauthorized)
                return
        }

        responseHeader := http.Header{}
        if protocols := websocket.Subprotocols(r); len(protocols) > 0 {
                responseHeader.Set("Sec-WebSocket-Protocol", protocols[0])
        }

        conn, err := upgrader.Upgrade(w, r, responseHeader)
        if err != nil {
                http.Error(w, "upgrade failed", http.StatusInternalServerError)
                return
        }
        defer conn.Close()

        _ = conn.WriteMessage(websocket.TextMessage, []byte("authenticated as "+token))
}
```

Enable the source in configuration with either `websocket_protocol` (for the default sentinel) or `websocket_protocol:custom`
to look for an alternative scheme name.

## Can handlers allow anonymous readers while still validating tokens when supplied?

Yes. Set `config.Config.AllowAnonymousRequests` to `true`. Requests without a bearer token will bypass authentication, while
requests that include a token will be validated normally. Within handlers call `viewer.IsAuthenticated(r.Context())` to
differentiate between anonymous and authenticated callers.

## Where do I find test helpers?

The `internal/testutil/issuer` package exposes a `FakeIssuer` server, JWT signing helpers, and JWKS responses for unit tests.

## Does the middleware support tracing and metrics?

Yes. Supply a `MetricsRecorder` implementation (e.g., `observability.NewMetrics`) and an OpenTelemetry `trace.Tracer` to capture spans and Prometheus-friendly metrics.
