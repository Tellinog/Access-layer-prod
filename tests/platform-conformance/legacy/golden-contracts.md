# Legacy golden contracts

The `fixtures/` directory contains synthetic, version-controlled shapes derived from the repository-observed Access Layer contract. They are validated by `tests/legacy-contract-baseline.test.ts` against `specs/legacy-contract-baseline.v1.json`.

Do not store real tokens, secrets, cookies, emails or provider subjects. Preserve only the fields and semantics required to prove compatibility.

Future consumer-specific fixtures, after provenance and registration verification, should use:

```text
legacy/
├── nancy/
├── test-generator/
├── petyr/
├── goodman/
└── internal-network/
```

Each consumer set should cover:

- auth start redirect and callback validation;
- one-time code exchange;
- response field names and nullability;
- JWT claims expected locally;
- refresh request/response and concurrency;
- active/inactive introspection;
- logout/revocation;
- representative permission decisions and errors.
