## 2026-02-26 - Security Warning for Empty Audiences
**Vulnerability:** Default OIDC middleware configuration allows tokens for any audience if `Audiences` list is empty.
**Learning:** This is a common pattern in OIDC libraries to be permissive by default for developer ease, but it introduces the "Confused Deputy" problem where a token issued for Service A is accepted by Service B.
**Prevention:** Explicitly check for empty audiences in configuration and log a warning to alert administrators of the potential risk.
