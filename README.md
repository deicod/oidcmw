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
