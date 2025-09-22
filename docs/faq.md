# Frequently Asked Questions

### Does the middleware refresh JWKS keys automatically?
Yes. The underlying `go-oidc` verifier caches keys and refreshes them when signatures fail. Configure your own `http.Client` to adjust cache lifetimes or retry behavior.

### Can I validate tokens from multiple issuers?
The current release focuses on a single issuer. Run multiple middleware instances or construct separate `http.ServeMux` paths when supporting multi-tenant issuers. Multi-issuer routing is on the roadmap.

### How do I enforce scope-based authorization?
Use the helper predicates on `viewer.Viewer` such as `HasAnyScope`. Combine them with your domain-specific authorization logic inside handlers.

### Is session management supported?
No. The middleware validates stateless bearer tokens. Integrate with your identity provider's refresh token flow or session management features externally.

### What happens if the issuer is temporarily unreachable?
Validation fails closed: requests are rejected with `invalid_token`. Configure retries and timeouts on the HTTP client and consider deploying local JWKS caches when network instability is expected.
