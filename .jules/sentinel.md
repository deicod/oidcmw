## 2026-02-26 - Security Warning for Empty Audiences
**Vulnerability:** Default OIDC middleware configuration allows tokens for any audience if `Audiences` list is empty.
**Learning:** This is a common pattern in OIDC libraries to be permissive by default for developer ease, but it introduces the "Confused Deputy" problem where a token issued for Service A is accepted by Service B.
**Prevention:** Explicitly check for empty audiences in configuration and log a warning to alert administrators of the potential risk.
## 2026-02-26 - Missing Expiry Claim Validation
**Vulnerability:** ID Tokens without `exp` or `iat` claims were silently bypassing expiration checks because `go-oidc`'s built-in expiry check was disabled to support custom clock skew.
**Learning:** When disabling library-provided validation checks (like `SkipExpiryCheck: true` in `go-oidc`), you must explicitly re-implement all implicit guarantees of the original check, including the presence of required fields.
**Prevention:** Always ensure mandatory fields like `exp` and `iat` are present before checking their values, especially when building custom temporal validation logic.
## 2026-03-04 - Missing Subject (sub) Claim Validation
**Vulnerability:** The middleware did not explicitly check for the presence of the `sub` (subject) claim in ID Tokens.
**Learning:** While `go-oidc` verifies signatures, some specific application-level claims like `sub` (which uniquely identifies the principal) need explicit validation if not natively enforced by the verifier configuration or when overriding library defaults. Missing this could lead to empty subjects or misattribution.
**Prevention:** Always ensure mandatory claims like `sub` are present and non-empty during token validation to prevent identity spoofing or nil principal scenarios downstream.
