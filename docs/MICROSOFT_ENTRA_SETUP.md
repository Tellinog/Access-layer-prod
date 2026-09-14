# Microsoft Entra setup for Testbirds sign-in

Status: updated for the approved temporary legacy bridge. Runtime support is implemented locally but remains default-off; no tenant/Coolify mutation, secret provisioning, deployment or production enablement has been performed.

## Purpose

This guide describes the information and Microsoft Entra configuration required to let Testbirds employees authenticate to Access Layer. Access Layer remains the only authentication and authorization broker used by tools. Individual tools must not receive Microsoft credentials or integrate directly with Microsoft Entra.

The approved temporary production callback is:

```text
https://access-layer.unguess-internal.net/v1/auth/microsoft/callback
```

The corresponding local callback under the current development base path is:

```text
http://localhost:8080/access-control/v1/auth/microsoft/callback
```

The production URI must still be registered and configured by an authorized operator before enablement.

## Recommended tenant model

Register Access Layer as a **single-tenant Web application** in the Testbirds workforce tenant. Do not use `common`, `organizations`, personal Microsoft accounts or a generic multi-tenant registration for the first rollout.

Access Layer must use a tenant-specific OpenID Connect authority and accept only the exact Testbirds tenant ID. The `testbirds.com` email suffix is an additional business check, not the primary trust boundary.

Recommended access policy:

- allow only tenant members, not guests;
- require assignment to the Enterprise Application;
- assign a dedicated pilot group or named pilot users first;
- apply the Testbirds Conditional Access and MFA policy to the Enterprise Application;
- keep Access Layer grants as the final per-tool authorization decision.

Microsoft documents single-tenant registration, redirect URI requirements, token claims, optional claims, user assignment and credentials here:

- https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app
- https://learn.microsoft.com/en-us/entra/identity-platform/reply-url
- https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow
- https://learn.microsoft.com/en-us/entra/identity-platform/id-tokens
- https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference
- https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims-reference
- https://learn.microsoft.com/en-us/entra/identity-platform/howto-restrict-your-app-to-a-set-of-users
- https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-credentials

## Entra administrator procedure

### 1. Confirm the directory

Before creating the application, confirm:

- the authoritative Testbirds workforce Directory (tenant) ID;
- that `testbirds.com` is a verified domain in that tenant;
- whether Testbirds users are tenant members or B2B guests;
- the Entra application owner and operational backup owner;
- whether group assignment and Conditional Access are licensed and required.

Do not use the tenant display name or domain string as the runtime trust identifier. Return the immutable Directory (tenant) ID.

### 2. Register the application

In Microsoft Entra admin center:

1. Open **Entra ID > App registrations > New registration**.
2. Use a clear name such as `UNGUESS Access Layer - Production`.
3. Select **Accounts in this organizational directory only**.
4. Complete the registration.
5. Record the **Application (client) ID**, **Directory (tenant) ID** and application **Object ID**.
6. Add at least two named owners if Testbirds policy permits it.

Use a separate development app registration where possible. Do not expose a localhost redirect on the production registration unless the Entra owner explicitly accepts it.

### 3. Configure the Web redirect

Under **Authentication > Add a platform > Web**, add the exact approved callback URI:

```text
https://access-layer.unguess-internal.net/v1/auth/microsoft/callback
```

Rules:

- production must use HTTPS;
- path case and trailing slash must match exactly;
- do not use wildcards;
- do not register a tool callback: Entra returns only to Access Layer;
- do not enable implicit access-token or ID-token issuance; the server-side authorization-code flow obtains the ID token at the token endpoint;
- keep production and local registrations separate where practical.

### 4. Configure identity scopes and claims

The baseline login requires only:

```text
openid profile email
```

`offline_access` is not required because Access Layer issues and manages its own session and refresh credentials. Microsoft Graph permissions are not used by the temporary bridge.

Under **Token configuration**, request `email` as an ID-token optional claim for the pilot when the directory does not emit it by default. The bridge may use a syntactically valid `preferred_username` only as the documented fallback. `oid`, `tid` and `nonce` remain mandatory runtime checks.

Access Layer validates the standard token signature and exact `iss`, `aud`, `exp`, `nonce`, `tid` and non-empty `oid` claims. `preferred_username`, UPN, display name and email are mutable and are not the stable user key.

If neither `email` nor `preferred_username` is a usable allowed-domain address, correct the directory claim configuration before enablement. Do not add Graph as an implicit fallback.

### 5. Restrict access to the Enterprise Application

Under **Enterprise applications**, open the service principal created for the app:

1. Set **Assignment required?** to `Yes`.
2. Grant tenant-wide admin consent if required by the assignment/consent policy.
3. Assign only the approved pilot users or group.
4. Record the Enterprise Application (service principal) Object ID.
5. Apply the approved Conditional Access/MFA policy.

Group-based assignment can require Entra ID P1 or P2 and does not include nested-group members automatically. Confirm the effective pilot membership rather than assuming nested groups are expanded.

### 6. Choose the application credential

The approved temporary bridge uses a client secret. Store it only in the approved runtime secret mechanism, record its expiry and rotation owner, and keep the bridge default-off until configuration is complete. Any future certificate/federated change is a separate implementation decision.

Never put the secret value, certificate private key or reusable verifier in Git, tickets, screenshots, chat transcripts or this repository. Transfer it directly into the approved secret manager/Coolify secret mechanism.

### 7. Do not expose an API unless required

This app registration authenticates users to Access Layer. It does not need an Application ID URI, custom API scope, app role or application permission for the baseline flow. Add those only after a separate product and security decision.

## Information to return to the Access Layer team

### Non-secret configuration

- Directory (tenant) ID.
- Confirmed tenant type: workforce tenant.
- Confirmation that `testbirds.com` is a verified tenant domain.
- Application (client) ID.
- Application Object ID.
- Enterprise Application/service-principal Object ID.
- Supported account type (`single tenant`).
- Exact production and development redirect URI lists.
- Tenant-specific OIDC issuer and discovery URL.
- Granted scopes/API permissions and admin-consent status.
- Configured ID-token optional claims.
- Whether assignment is required.
- Whether guests are assigned or permitted.
- Pilot assignment method (named users or group) and operational owner. Do not commit sensitive membership lists.
- Conditional Access/MFA owner and confirmation that the pilot policy is applied.
- Credential type, public certificate thumbprint when applicable, activation date, expiry date and rotation owner.

### Secret delivery

Deliver exactly one of the approved credential sets through the protected operational channel:

- client-secret value for the approved temporary application registration.

The repository should receive only environment-variable names, public certificate metadata and redacted evidence.

## Planned Access Layer validation

The Microsoft adapter must reject the login unless all applicable checks pass:

- signature verified from the tenant-specific OIDC metadata/JWKS;
- exact `aud` equals the registered Application (client) ID;
- exact v2 issuer matches the approved tenant-specific issuer;
- `tid` is the approved Testbirds tenant GUID and matches the issuer;
- `oid` is present and well formed;
- `nonce` matches the hash-bound authorization transaction;
- `exp` is present and unexpired;
- `email`, or the documented `preferred_username` fallback, is valid, normalized and belongs to an allowed domain;
- the Access Layer user, tool and grant are active.

The stable Microsoft identity key is the tuple `(tid, oid)`, represented in the frozen legacy contract as `msft:<tid>:<oid>`. Email, UPN and `preferred_username` are display/contact attributes only and never cross-provider linking keys.

## Pilot test evidence

Use synthetic or designated test accounts and record no credentials or tokens:

- assigned Testbirds member with active Access Layer grant: allowed;
- assigned Testbirds member without grant: authenticated, then denied/request queued according to policy;
- unassigned Testbirds member: denied by Entra;
- guest account: denied;
- account from another tenant or personal Microsoft account: denied;
- missing/wrong nonce, audience, issuer, tenant or object ID: denied;
- missing/invalid/non-Testbirds email policy input: denied;
- existing UNGUESS Google login remains unchanged;
- legacy sessions, refresh, introspection, logout and tool callback behavior survive the release.
