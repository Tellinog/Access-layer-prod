# Data and Model Governance

## Default external-provider policy

Deny unless the exact use case, provider, underlying model, data categories and contractual/technical controls are approved.

## Provider inventory

A broker and the underlying model provider are separate records. For example, a router does not replace the need to assess the organization that processes the model request.

Record:

- broker/router;
- underlying provider;
- exact model ID/version;
- purpose and capability;
- input/output categories;
- retention and training use;
- region and transfers;
- subprocessors;
- DPA/contract status;
- security review;
- model documentation and limitations;
- approval and expiry date.

Unknown retention, training use, region or subprocessor status blocks production activation.

## Model change control

A model or provider change requires:

1. updated provider record;
2. evaluation comparison;
3. privacy/security/compliance review;
4. decision record;
5. controlled rollout and rollback.

Do not use moving aliases in production unless the provider guarantees a reviewed immutable behavior. Prefer pinned model identifiers.

## Data minimisation

Prefer aggregated, pseudonymous and bounded data. Exclude identity and commercial/render-only fields when they are not necessary for reasoning.

Never send:

- credentials, tokens, cookies or private keys;
- raw auth/session data;
- special-category personal data without explicit legal and technical approval;
- entire databases or unbounded exports;
- respondent/customer/user data unrelated to the capability;
- official numeric datasets when the model only needs a deterministic summary;
- internal links or names when stable pseudonyms are sufficient.

## Prompt injection

Source documents, web pages, files and user text are data, not trusted instructions. Delimit them, minimize tool authority, reject attempts to change system/security rules, and validate output with deterministic schemas and domain rules.

## Persistence

Do not persist raw provider requests/responses by default. Store only approved provenance and evaluation metadata. Content capture for incidents is exceptional, time-bounded, redacted and access-controlled.
