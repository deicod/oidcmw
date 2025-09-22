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
