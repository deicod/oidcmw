# Implementation Plan for OIDC Middleware

## Overview
This document translates the product requirements into an actionable engineering plan with iteration milestones and detailed todos.

## Iteration Plan

### Iteration 1: Middleware Foundation & Token Validation
- Establish repository structure, base packages, and configuration scaffolding.
- Implement core middleware constructor `NewMiddleware` with request wrapping.
- Add bearer token extraction from Authorization header and configurable sources.
- Integrate OIDC client (`github.com/coreos/go-oidc`) and OAuth2 HTTP client setup.
- Implement JWKS fetching, caching, and rotation logic with configurable timeouts.
- Validate token signature, expiration (`exp`), issued-at (`iat`), not-before (`nbf`), issuer (`iss`), audience (`aud`), type (`typ`), and authorized party (`azp`).
- Provide structured error responses with configurable status codes and error body schema.
- Add unit tests covering middleware happy path and common failure scenarios.

### Iteration 2: Viewer & Authorization Helpers
- Define `Viewer` struct and context helpers for retrieving validated identity data.
- Map claims to viewer attributes (subject, username, email, names).
- Parse role claims from `realm_access` and `resource_access`, preserving raw claims.
- Implement helper predicates (`HasRealmRole`, `HasResourceRole`, `HasAnyScope`).
- Add scope parsing utilities and tests.
- Ensure middleware populates viewer in context and guards against missing viewer access.

### Iteration 3: Configuration & Extensibility
- Finalize `Config` struct to cover issuer, audiences, token types, azp, role extraction toggles, error responses, and hooks.
- Provide helper loaders for environment variables and declarative files.
- Support pluggable token sources (cookies, custom headers, optional query params) via interfaces.
- Expose hooks for custom claim validation and authorization policies.
- Harden HTTP client configuration (timeouts, transport, mTLS support).
- Document configuration examples.

### Iteration 4: Observability, Tooling & Docs
- Integrate structured logging with user-supplied logger abstraction.
- Emit Prometheus metrics for validation outcomes and latency.
- Provide tracing hooks compatible with OpenTelemetry.
- Supply test doubles (fake issuer, signing key utilities) for unit/integration tests.
- Author example applications, quick-start guides, and troubleshooting docs.
- Ensure `go test`, `go vet`, and `staticcheck` run cleanly in CI.

## Cross-Cutting Concerns
- Maintain defensive coding standards, fail closed on errors, and sanitize logs.
- Ensure concurrency safety across shared caches and configuration updates.
- Plan for dynamic configuration reloads without restarts where feasible.
- Enforce privacy guidelines by limiting PII exposure and following OAuth2/OIDC specifications.

## Detailed TODOs
- [ ] Scaffold middleware package structure and configuration types.
- [ ] Implement token extraction utilities for Authorization header, cookies, and custom headers.
- [ ] Set up OIDC provider client, JWKS cache, and signature verification.
- [ ] Enforce claim validation checks with configurable policies.
- [ ] Implement request context enrichment with viewer and raw claims.
- [ ] Build authorization helper functions and role/scope parsing.
- [ ] Expose extension hooks for custom validation and token sources.
- [ ] Add structured error handling, logging, and metrics instrumentation.
- [ ] Create test doubles and comprehensive unit/integration test suites.
- [ ] Write developer documentation, examples, and migration guides.
- [ ] Configure CI scripts to run `go test`, `go vet`, and `staticcheck`.

## Open Questions & Risks
- Define strategy for dynamic configuration reloads (file watch vs. API-driven updates).
- Decide on default logger interface (standard library vs. abstract interface).
- Evaluate optional rate limiting integration or guidance for brute force mitigation.

