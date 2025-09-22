# Implementation Plan for OIDC Middleware

## Overview
This document translates the product requirements into an actionable engineering plan with iteration milestones, detailed task
breakdowns, and measurable acceptance criteria.  The roadmap assumes a small team (2 engineers + 1 reviewer/tech writer) and c
an be adapted for parallel execution if additional contributors join.

## Iteration Plan

Each iteration below lasts roughly one week and is scoped to produce a demonstrable increment.  Every iteration concludes with
a review walkthrough, updated documentation, and a regression test run (`go test ./...`, `go vet ./...`, `staticcheck ./...`).

### Iteration 1: Middleware Foundation & Token Validation
**Goals**
- Deliver a compilable middleware skeleton capable of rejecting invalid tokens and passing minimal smoke tests.
- Lay the groundwork for future extensions without breaking API expectations.

**Scope & Tasks**
- Establish repository structure, base packages, and configuration scaffolding including `middleware`, `config`, and `internal/oidc` packages.
- Implement core middleware constructor `NewMiddleware` with request wrapping and dependency injection for OIDC provider clients.
- Add bearer token extraction from the Authorization header and an extensible token source interface for future providers.
- Integrate OIDC client (`github.com/coreos/go-oidc`) and OAuth2 HTTP client setup with retry-capable transport.
- Implement JWKS fetching, caching, and rotation logic with configurable timeouts and background refresh.
- Validate token signature, expiration (`exp`), issued-at (`iat`), not-before (`nbf`), issuer (`iss`), audience (`aud`), type (`typ`), and authorized party (`azp`).
- Provide structured error responses with configurable status codes and error body schema, ensuring sensitive claim data stays redacted.

**Deliverables**
- Middleware package exposing `NewMiddleware` and token validation primitives.
- Unit tests covering middleware happy path, signature failures, claim violations, JWKS refresh failure, and malformed token parsing.
- Documentation page describing required configuration values for a basic deployment.

**Testing & Acceptance Criteria**
- Automated tests stubbing out JWKS endpoints pass.
- Running the middleware against a local Keycloak/Okta issuer using sample tokens validates positive and negative flows.

### Iteration 2: Viewer & Authorization Helpers
**Goals**
- Surface validated identity information to downstream handlers in a type-safe manner.
- Provide helper utilities to simplify authorization checks.

**Scope & Tasks**
- Define `Viewer` struct and context helpers for retrieving validated identity data while guarding against missing viewers.
- Map claims to viewer attributes (subject, username, email, given/family names) with normalization helpers for optional fields.
- Parse role claims from `realm_access` and `resource_access`, preserving raw claims and capturing unknown namespaces.
- Implement helper predicates (`HasRealmRole`, `HasResourceRole`, `HasAnyScope`) with defensive nil checks and table-driven tests.
- Add scope parsing utilities including support for space-delimited, array, and custom claim formats.
- Ensure middleware populates the viewer in context and denies access when downstream handlers request a viewer but none exists.

**Deliverables**
- `viewer` package with exported helpers and documentation examples.
- Expanded unit tests verifying context propagation, claim parsing edge cases, and helper predicates.
- Example handler snippet demonstrating role/scope enforcement.

**Testing & Acceptance Criteria**
- Viewer extraction functions achieve >90% branch coverage with unit tests.
- Manual smoke test with sample JWT ensures viewer data accessible via context.

### Iteration 3: Configuration & Extensibility
**Goals**
- Provide ergonomic configuration options and extensibility hooks enabling diverse deployment topologies.
- Decouple configuration loading from middleware construction for reuse in CLIs and integration tests.

**Scope & Tasks**
- Finalize `Config` struct to cover issuer, audiences, token types, `azp`, role extraction toggles, error responses, and lifecycle hooks.
- Provide helper loaders for environment variables, declarative YAML/JSON files, and programmatic defaults with validation errors.
- Support pluggable token sources (cookies, custom headers, optional query params) via interfaces with built-in implementations.
- Expose hooks for custom claim validation and authorization policies using functional options.
- Harden HTTP client configuration (timeouts, transport, mTLS support) and document how to inject custom transports.
- Document configuration examples, including multi-tenant issuer selection and fallback behavior.

**Deliverables**
- Configuration loader utilities with integration tests verifying precedence rules.
- Sample configuration files stored under `examples/config/`.
- Extensibility guide covering token source plugins and custom validation hooks.

**Testing & Acceptance Criteria**
- Configuration validation rejects invalid combinations (e.g., missing issuer, conflicting token types).
- Integration tests simulate multiple token sources and verify correct precedence.

### Iteration 4: Observability, Tooling & Docs
**Goals**
- Provide operational visibility and developer ergonomics necessary for production readiness.
- Ship documentation and tooling enabling rapid adoption.

**Scope & Tasks**
- Integrate structured logging with user-supplied logger abstraction, defaulting to `log/slog` compatibility.
- Emit Prometheus metrics for validation outcomes and latency with customizable namespace/prefix.
- Provide tracing hooks compatible with OpenTelemetry, including span attributes for issuer and subject (without leaking PII).
- Supply test doubles (fake issuer, signing key utilities) for unit/integration tests, accompanied by guidance for usage.
- Author example applications, quick-start guides, and troubleshooting docs hosted under `docs/` and `examples/`.
- Ensure `go test`, `go vet`, and `staticcheck` run cleanly in CI with GitHub Actions workflow definitions.

**Deliverables**
- `observability` package exporting metrics registration and tracing helpers.
- Test utilities consumable by downstream integrators.
- Comprehensive documentation set including README updates, quick-start, configuration reference, troubleshooting, and FAQ.
- CI pipeline configuration checked into `.github/workflows/ci.yaml`.

**Testing & Acceptance Criteria**
- Metrics recorded in unit tests using `prometheus/testutil`.
- Tracing hooks verified via integration test ensuring spans propagate context.
- Documentation reviewed for accuracy with sample copy/paste instructions tested manually.

## Dependencies & Tooling
- **Third-party libraries**: `github.com/coreos/go-oidc`, `golang.org/x/oauth2`, `github.com/prometheus/client_golang`, `go.opentelemetry.io/otel`.
- **Testing stack**: `stretchr/testify` for assertions/mocks, built-in `httptest`, and local fake issuer utility.
- **CI/CD**: GitHub Actions runners with Go 1.22.x, caching for module downloads, and `staticcheck` installation step.
- **Sample identity providers**: Dockerized Keycloak realm and mock JWKS server for integration tests.
- **Documentation tooling**: `mdbook` or MkDocs (to be finalized) for publishing guides in Iteration 4.

## Cross-Cutting Concerns
- **Security & Privacy**: Maintain defensive coding standards, fail closed on errors, sanitize logs, and ensure sensitive claims are never logged or exported unintentionally.
- **Performance & Concurrency**: Ensure concurrency safety across shared caches and configuration updates; benchmark token validation throughput with representative load (target P95 < 15ms per request with warm cache).
- **Resilience**: Provide circuit-breaker or retry strategies for JWKS and issuer metadata fetches; design fallbacks for temporarily unavailable issuers.
- **Configuration Reloadability**: Plan for dynamic configuration reloads without restarts via hot-swappable config handles guarded by RWMutexes and validation hooks.
- **Documentation Discipline**: Keep README, API docs, and examples synchronized with code changes per iteration review checklist.

## Timeline & Milestones
| Week | Iteration | Milestone | Exit Criteria |
| ---- | ---------- | --------- | ------------- |
| 1 | Iteration 1 | Middleware foundation merged | All Iteration 1 acceptance criteria met; smoke tests with sample issuer succeed. |
| 2 | Iteration 2 | Viewer helpers released | Viewer context helpers stable; documentation added; >90% branch coverage for viewer package. |
| 3 | Iteration 3 | Configuration toolkit available | Config loaders with validation shipped; extensibility guide published; integration tests green. |
| 4 | Iteration 4 | Production readiness | Observability stack in place; CI pipeline operational; documentation set complete. |

## Detailed TODOs

### Iteration 1 Checklist
- [ ] Scaffold middleware, config, and internal OIDC packages with buildable skeletons.
- [ ] Implement Authorization header token extractor and interface for alternative sources.
- [ ] Wire OIDC provider client, JWKS cache, and signature verification with configurable timeouts.
- [ ] Enforce baseline claim validation (`exp`, `iat`, `nbf`, `iss`, `aud`, `typ`, `azp`).
- [ ] Provide structured error responses and redact sensitive claim data.
- [ ] Author unit tests for happy path, invalid signature, expired token, and JWKS fetch failure.

### Iteration 2 Checklist
- [ ] Define `Viewer` struct and context accessor helpers.
- [ ] Map standard claims to viewer fields with normalization logic and tests.
- [ ] Implement realm/resource role parsing preserving unknown roles.
- [ ] Add scope parsing utilities supporting multiple claim formats.
- [ ] Expose authorization helper predicates with table-driven tests.
- [ ] Document viewer usage with example handler snippet.

### Iteration 3 Checklist
- [ ] Finalize `Config` struct covering issuer, audiences, token sources, error policy, and hooks.
- [ ] Build env var and file-based config loaders with precedence rules and validation errors.
- [ ] Implement cookie, custom header, and query param token sources registered via interface.
- [ ] Add custom claim validation hook support and sample usage tests.
- [ ] Harden HTTP client configuration (timeouts, retry policy, mTLS) and document overrides.
- [ ] Publish extensibility guide and sample configuration files.

### Iteration 4 Checklist
- [ ] Integrate structured logging abstraction with context awareness.
- [ ] Emit Prometheus metrics and expose registration helper.
- [ ] Provide OpenTelemetry tracing hooks with span attribute safeguards.
- [ ] Create fake issuer, signer utilities, and helper packages for tests.
- [ ] Author quick-start, troubleshooting, FAQ, and update README index.
- [ ] Add GitHub Actions workflow running `go test`, `go vet`, and `staticcheck`.

## Open Questions & Risks
| Item | Current Understanding | Proposed Resolution |
| ---- | --------------------- | ------------------- |
| Dynamic configuration reloads | Needed for long-lived services, mechanism undecided. | Prototype watcher-based reload in Iteration 3, fall back to documented restart procedure if complexity too high. |
| Default logger interface | Unsure whether to expose stdlib logger or abstract interface. | Adopt minimal interface compatible with `log/slog` and document adapter pattern; revisit once community feedback gathered. |
| Rate limiting guidance | Brute force mitigation mentioned but not scoped. | Provide documentation sidebar referencing upstream reverse proxies and recommend using external rate limit middleware; deprioritize built-in rate limiting for v1.0. |
| Token source precedence | Multiple token sources may conflict. | Define deterministic priority order (Authorization header > cookie > query param) and enforce via integration tests in Iteration 3. |
| Multi-tenant issuer support | Requirement unclear beyond single issuer. | Design configuration to optionally map audiences to issuers; gather stakeholder feedback before expanding scope. |

## Definition of Done
- All iteration checklists completed and verified by peer review.
- CI pipeline green with `go test ./...`, `go vet ./...`, and `staticcheck ./...` passing on main branch.
- Documentation set (README, configuration reference, quick-start, troubleshooting, FAQ) published and internally reviewed.
- Example applications run successfully against the sample Keycloak realm with documented setup steps.
- Observability hooks (logging, metrics, tracing) validated in a staging environment with sample instrumentation.
- Outstanding risks either mitigated, accepted with rationale, or deferred with explicit roadmap item.

