## 2025-05-21 - Defer Unmarshaling for OIDC Token Validation
**Learning:** `go-oidc` parses standard claims (iss, aud, exp, iat) into `IDToken` struct fields during verification. We can use these fields to validate the token *before* unmarshaling the full claims map, which is expensive. This avoids JSON unmarshaling for tokens that fail basic checks (expiry, issuer, audience).
**Action:** When using `go-oidc`, always check `IDToken` fields first before unmarshaling claims if you need to validate standard claims.
