# Product Requirements Document: Go OpenID Connect Middleware

## 1. Product Overview
Build a production-grade OpenID Connect (OIDC) middleware package for Go's `net/http` standard library, targeting `http.ServeMux` and compatible handlers. The middleware must authenticate and authorize incoming HTTP requests by validating bearer access tokens, enriching the request context with relevant identity data, and enforcing fine-grained access controls. Security is the top priority and all design decisions must favor correctness, defense-in-depth, and maintainability.

## 2. Background & Problem Statement
Service teams running Go HTTP services need a lightweight yet secure way to protect endpoints using OIDC-compliant identity providers. Rolling custom token checks is error-prone and difficult to keep current with evolving security practices. Existing solutions are either overly coupled to third-party frameworks or lack the configurability and assurance required for sensitive workloads. We need a library that is idiomatic to Go, easy to embed into existing `net/http` stacks, and rigorously validates tokens while giving developers high-level primitives to work with identities and roles.

## 3. Goals
- Provide drop-in middleware that guards handlers behind OIDC token verification.
- Offer configurable verification for issuer (`iss`), audience (`aud`), token type (`typ`), and authorized party (`azp`).
- Support Keycloak-style token claim structures, including the provided access token schema.
- Expose convenience helpers ("viewer" pattern) to extract claims, roles, and metadata from validated tokens.
- Maximize security posture through strict validation, defensive coding, and least privilege defaults.
- Deliver comprehensive documentation, examples, and tests to instill confidence and ease adoption.

## 4. Non-Goals
- Replace full-featured OAuth2 clients or token acquisition flows.
- Provide UI components or API gateways.
- Manage refresh tokens, session storage, or persistence of user data.
- Support non-HTTP transports (e.g., gRPC) in the initial release.

## 5. Target Users & Personas
- **Go Service Developer**: Maintains APIs using `net/http` and needs reliable auth protection without adopting a new web framework.
- **Security Engineer**: Audits authentication controls, requires configurable validation and visibility into failures.
- **Platform Engineer**: Integrates middleware into platform templates and expects compatibility with common proxies and load balancers.

## 6. User Stories
1. *As a Go developer*, I can wrap my handlers with the middleware so that only requests with valid access tokens reach my business logic.
2. *As a security engineer*, I can configure allowed issuers, audiences, token types, and authorized parties to enforce policy without code changes.
3. *As a platform engineer*, I can introspect the request context to determine the caller's roles and identity for downstream authorization decisions.
4. *As a developer*, I can log and observe authentication failures for troubleshooting while avoiding sensitive data leakage.
5. *As a developer*, I can write unit tests using test helpers and mocks to simulate token validation outcomes.

## 7. Functional Requirements
### 7.1 Middleware Core
- Expose a package (e.g., `oidcmw`) with a constructor function `NewMiddleware(config Config) (func(http.Handler) http.Handler, error)`.
- Middleware must:
  - Extract bearer tokens from the `Authorization` header using the `Bearer` scheme.
  - Support optional token retrieval from cookies or custom headers through configuration.
  - Validate tokens before invoking the next handler; unauthorized requests must yield configurable HTTP status codes and structured error responses.
  - Attach validated token claims and derived viewer/role information to the request context for downstream handlers.
  - Ensure middleware is safe for concurrent use.

### 7.2 Token Validation
- Integrate with a well-maintained OIDC client (e.g., `golang.org/x/oauth2` & `github.com/coreos/go-oidc`).
- Fetch and cache JSON Web Key Sets (JWKS) securely with configurable refresh intervals and timeout handling.
- Validate signature, expiration (`exp`), issued-at (`iat`), and not-before (`nbf` if present) claims.
- Enforce issuer (`iss`), audience (`aud`), token type (`typ`), and authorized party (`azp`) checks with configuration supporting:
  - Exact match, allow-lists, and optional wildcards where appropriate.
  - Per-resource audience lists for multi-tenant services.
  - Ability to disable individual checks explicitly (default: all enabled with strict matching).
- Ensure the provided Keycloak-style claim structure is supported, including parsing nested `realm_access.roles` and `resource_access` maps.
- Provide robust error classification (e.g., invalid token, expired, signature mismatch, claim mismatch) for logging and metrics.

#### 7.2.1 Reference Access Token Claims
The middleware must correctly interpret the following canonical access token shape issued by the target identity provider. Claims not listed must be preserved for downstream consumers but only trusted when validated by the middleware.

```json
{
  "exp": 1758539593,
  "iat": 1758539293,
  "jti": "onrtna:45568d04-4a6e-b227-db30-097768153fc6",
  "iss": "https://auth.icod.de/realms/dev",
  "aud": "account",
  "sub": "1d2e3000-8eba-4c30-9a09-1ca7c00df751",
  "typ": "Bearer",
  "azp": "spa",
  "sid": "2273462b-ce2a-4e93-a2aa-0983631e22b3",
  "acr": "1",
  "allowed-origins": ["*"],
  "realm_access": {
    "roles": [
      "default-roles-dev",
      "offline_access",
      "uma_authorization"
    ]
  },
  "resource_access": {
    "account": {
      "roles": [
        "manage-account",
        "manage-account-links",
        "view-profile"
      ]
    }
  },
  "scope": "openid email profile",
  "email_verified": true,
  "name": "Darko Luketic",
  "preferred_username": "dalu",
  "given_name": "Darko",
  "family_name": "Luketic",
  "email": "info@icod.de"
}
```
- Document how each claim maps to viewer attributes and authorization helpers.
- Provide extension points for custom claim extraction beyond the reference schema.

### 7.3 Authorization Helpers (Viewer Pattern)
- Define a `Viewer` interface/struct populated from validated claims containing:
  - `Subject`, `PreferredUsername`, `Email`, `Name`, `GivenName`, `FamilyName`.
  - `RealmRoles []string` extracted from `realm_access.roles`.
  - `ResourceRoles map[string][]string` extracted from `resource_access`.
  - `Scopes []string` parsed from the `scope` claim.
- Provide helper functions such as `viewer.FromContext(ctx)` to retrieve the viewer or fail fast if absent.
- Include utility predicates: `viewer.HasRealmRole(role string)`, `viewer.HasResourceRole(resource, role string)`, `viewer.HasAnyScope(scopes ...string)`, etc.
- Preserve original raw claims for advanced use cases while shielding sensitive data (e.g., tokens) from logs.

### 7.4 Configuration & Extensibility
- Define a `Config` struct with fields for:
  - Issuer URL, Client ID(s), allowed audiences, token type(s), authorized parties.
  - HTTP client configuration (timeouts, custom transport, mTLS certificates).
  - Optional cache settings for JWKS and discovery documents.
  - Error response templates and localization hooks.
  - Hooks for custom claim validation and authorization policies.
  - Toggle for enabling/disabling role extraction or viewer creation.
- Support configuration via code, environment variables, or declarative files (provide helper loaders).
- Offer pluggable token sources to enable advanced extraction (e.g., query params for legacy clients) while discouraging insecure patterns.

### 7.5 Observability & Error Handling
- Emit structured logs (with log abstraction to allow user-provided logger) on authentication outcomes without leaking secrets.
- Expose Prometheus-compatible metrics (e.g., token validation latency, error counts by type).
- Provide trace-friendly hooks (e.g., context propagation) to integrate with OpenTelemetry.
- Return standards-compliant errors using RFC 6750 where applicable.

### 7.6 Testing & Tooling
- Supply test doubles for token validation (e.g., signing key generators, fake issuers) to ease unit and integration testing.
- Include example tests demonstrating middleware usage and viewer role checks.
- Ensure CI pipelines run `go test`, `go vet`, and `staticcheck`.

## 8. Non-Functional Requirements
### 8.1 Security
- Default to denying access when validation cannot be performed (fail closed).
- Implement strict input validation, avoid string parsing vulnerabilities, and sanitize logs.
- Verify TLS certificates for issuer endpoints; support pinning/explicit CA bundles.
- Protect against replay attacks by enforcing expiration and optionally checking `jti` via user hooks.
- Offer rate limiting hooks or integration guidance for mitigating brute force attacks.
- Conduct regular dependency audits and document patching processes.

### 8.2 Performance
- Middleware should add minimal latency (<5 ms p95) after initial JWKS cache warm-up.
- Efficiently cache OIDC discovery and JWKS data with background refresh to prevent blocking.
- Minimize allocations and avoid global locks for per-request processing.

### 8.3 Reliability & Availability
- Handle transient network failures gracefully with retries and fallback to cached keys when safe.
- Provide health check endpoints or utilities to verify issuer connectivity.
- Support hot-reload or dynamic configuration updates without process restarts when possible.

### 8.4 Compliance & Privacy
- Avoid storing PII beyond request lifetime unless explicitly configured.
- Comply with OAuth2 and OIDC specifications; document deviations.
- Offer guidance for GDPR compliance (e.g., data minimization, request logging best practices).

### 8.5 Documentation & Developer Experience
- Provide README guides, quick-start examples, and API documentation via GoDoc.
- Publish migration guide for integrating into existing `http.ServeMux` apps.
- Offer troubleshooting guide covering common misconfigurations.

## 9. Success Metrics
- 100% of requests with invalid tokens are rejected in integration tests.
- Median integration latency overhead < 2 ms; p95 < 5 ms under expected load.
- Achieve >90% unit test coverage for middleware core and token validation components.
- Zero critical security issues reported during internal security review.
- Positive developer feedback (>=4/5 satisfaction) from pilot teams.

## 10. Assumptions & Dependencies
- Identity providers follow OIDC Discovery and provide JWKS endpoints (Keycloak baseline).
- Services operate in environments with stable outbound HTTPS connectivity to IdP.
- Consumers can upgrade Go runtime to at least Go 1.21.

## 11. Risks & Mitigations
- **Risk:** JWKS rotation causing token validation failures.
  - *Mitigation:* Implement background refresh, retries, and caching with grace periods.
- **Risk:** Misconfiguration leading to unintended access.
  - *Mitigation:* Provide safe defaults, configuration validation, and warnings for lax settings.
- **Risk:** Performance regressions due to heavy claim processing.
  - *Mitigation:* Optimize parsing, allow role extraction toggling, benchmark regularly.
- **Risk:** Dependency vulnerabilities.
  - *Mitigation:* Use minimal dependencies, monitor advisories, automate `go list -m -u` checks.

## 12. Milestones
1. **MVP (4 weeks)**: Core middleware with token validation, configurable `iss`/`aud`, viewer extraction, basic docs.
2. **Hardening (2 weeks)**: Metrics, structured logging, advanced configuration, security review.
3. **GA Release (2 weeks)**: Performance tuning, documentation polish, example apps, official v1.0.0 release.

## 13. Acceptance Criteria
- Middleware rejects requests lacking valid tokens or failing claim checks, returning RFC 6750 compliant errors.
- Context contains viewer object with roles and identity extracted from the provided claim structure.
- Configuration allows enabling/disabling or customizing validation of `iss`, `aud`, `typ`, and `azp` fields.
- Documentation explains setup, configuration options, and security considerations.
- Automated tests cover success and failure scenarios including malformed tokens and claim mismatches.
