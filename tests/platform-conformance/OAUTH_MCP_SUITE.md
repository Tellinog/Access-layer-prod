# OAuth P0 and future OAuth/OIDC/MCP conformance suite

Minimum acceptance cases:

- discovery metadata is internally consistent;
- PKCE-less and `plain` requests are rejected;
- incorrect code verifier and reused authorization code are rejected;
- redirect URI requires exact match;
- client cannot request an unregistered resource or scope;
- token audience is one resource and another resource rejects it;
- refresh token rotates; replay revokes the family;
- client suspension and entitlement revocation prevent renewal;
- human `sub` is the stable Google `sub` and OAuth access tokens are PII-minimised;
- client and resource identities remain distinct through the explicit entitlement bridge;
- signing keys rotate with overlap;
- protected-resource metadata is discoverable;
- MCP uses bearer headers, validates Origin and returns correct `401`/`403` challenges;
- tool discovery is scope-filtered;
- mutating tools require idempotency and declared confirmation;
- a real remote MCP client completes a read-only capability through Agent Gateway.

P0 covers Authorization Code, Refresh Token, metadata, revocation, introspection, token profile and registration contracts only. Service principals, `client_credentials`, token exchange, downstream OIDC, `private_key_jwt`, dynamic registration and MCP runtime cases are P1/deferred and must not be advertised by P0 metadata.
