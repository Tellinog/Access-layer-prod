# ARCHITECTURE_OVERVIEW.md

```mermaid
sequenceDiagram
    participant U as User browser
    participant T as Internal tool
    participant A as Access Layer
    participant G as Google OIDC
    participant DB as Database

    U->>T: Open protected page
    T->>U: Redirect to Access Layer /auth/start
    U->>A: tool_slug + return_url + tool_state
    A->>DB: Log auth.requested
    A->>G: Redirect authorization request
    G->>U: Google login/account selection
    G->>A: Callback with code + state
    A->>G: Exchange code server-side
    G->>A: ID token
    A->>A: Validate signature, aud, iss, exp, hd
    A->>DB: Upsert user, check grant, log decision
    A->>U: Redirect to tool callback with one-time code
    U->>T: callback?code=...&state=...
    T->>A: POST /auth/exchange with tool credentials
    A->>DB: Consume code, create session, log token.exchanged
    A->>T: User profile + permissions + Access Layer JWT
    T->>U: Local tool session
    U->>T: Later authenticated activity
    T->>A: POST /auth/refresh with tool credentials + current refresh token
    A->>DB: Consume token, revalidate, extend session, store replacement
    A->>T: New JWT + rotated refresh token
```

## Trust boundaries

- Browser is not trusted for identity, permissions or token integrity.
- Tool frontend is not trusted to hold tool secrets.
- Tool backend is trusted only after client authentication.
- Google ID token is trusted only after server-side validation.
- Access Layer JWT is trusted only after signature, issuer, audience and expiration checks.
