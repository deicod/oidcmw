## 2026-02-26 - Security Warning for Empty Audiences
**Vulnerability:** Default OIDC middleware configuration allows tokens for any audience if `Audiences` list is empty.
**Learning:** This is a common pattern in OIDC libraries to be permissive by default for developer ease, but it introduces the "Confused Deputy" problem where a token issued for Service A is accepted by Service B.
**Prevention:** Explicitly check for empty audiences in configuration and log a warning to alert administrators of the potential risk.
## 2026-02-26 - Missing Expiry Claim Validation
**Vulnerability:** ID Tokens without `exp` or `iat` claims were silently bypassing expiration checks because `go-oidc`'s built-in expiry check was disabled to support custom clock skew.
**Learning:** When disabling library-provided validation checks (like `SkipExpiryCheck: true` in `go-oidc`), you must explicitly re-implement all implicit guarantees of the original check, including the presence of required fields.
**Prevention:** Always ensure mandatory fields like `exp` and `iat` are present before checking their values, especially when building custom temporal validation logic.
