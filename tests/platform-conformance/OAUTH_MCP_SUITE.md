# OAuth/OIDC and MCP conformance suite

Minimum acceptance cases:

- discovery metadata is internally consistent;
- PKCE-less and `plain` requests are rejected;
- incorrect code verifier and reused authorization code are rejected;
- redirect URI requires exact match;
- client cannot request an unregistered resource or scope;
- token audience is one resource and another resource rejects it;
- refresh token rotates; replay revokes the family;
- client suspension and entitlement revocation prevent renewal;
- service and human principals remain distinct;
- token exchange cannot expand scope or delegation depth;
- signing keys rotate with overlap;
- protected-resource metadata is discoverable;
- MCP uses bearer headers, validates Origin and returns correct `401`/`403` challenges;
- tool discovery is scope-filtered;
- mutating tools require idempotency and declared confirmation;
- a real remote MCP client completes a read-only capability through Agent Gateway.
