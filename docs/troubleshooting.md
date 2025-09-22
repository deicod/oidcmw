# Troubleshooting

Common issues and suggested resolutions when integrating the middleware.

## Invalid Audience

- **Symptom**: Responses contain `{"error":"invalid_token"}` with logs mentioning `audience claim not allowed`.
- **Fix**: Ensure the configured audiences match the `aud` claim in issued tokens. Wildcards are not supported; list every acceptable audience explicitly.

## JWKS Fetch Failures

- **Symptom**: Validation fails with `token verification failed` and the middleware logs network errors.
- **Fix**: Verify outbound connectivity to the issuer, check firewall rules, and confirm the issuer's JWKS endpoint is reachable. Override `config.Config.HTTPClient` to add custom transports, proxies, or TLS settings when necessary.

## Token Type Mismatch

- **Symptom**: Requests fail after enabling `TokenTypes` with `token type not allowed`.
- **Fix**: Inspect the `typ` header of access tokens. Many providers omit this field from the claim set; remove the restriction unless your provider explicitly supplies it.

## Clock Skew Errors

- **Symptom**: Recently issued tokens are rejected with `token used before issued` or `token is not yet valid`.
- **Fix**: Adjust `config.Config.ClockSkew` to match the maximum difference between the issuer and service clocks. The default tolerance is 30 seconds.

## Missing Viewer in Context

- **Symptom**: Handlers calling `viewer.FromContext` receive `viewer: viewer not found in context`.
- **Fix**: Confirm the handler is wrapped with the middleware and that no other middleware replaces the request context. If you store the viewer before calling downstream handlers, forward the derived context explicitly.
