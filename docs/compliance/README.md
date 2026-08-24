# AI Governance and AI Act Readiness

Every project keeps this dossier, including projects declaring `no_ai`.

The dossier is a technical and organisational baseline. It does not automatically classify or legally certify a system. Final role, risk, privacy and conformity decisions require the named human owners and, where appropriate, legal/DPO review.

## Release gate

When `ai.enabled: true`, production is blocked until:

- intended purpose is approved;
- provider/deployer roles are assessed;
- prohibited-practice and Annex III screening are complete;
- Article 50 transparency is assessed and implemented where applicable;
- data boundary and provider/model register are approved;
- human oversight is implemented and tested;
- evaluation thresholds pass;
- incident owner and AI literacy measures are documented.

## Reference implementation patterns from the attached projects

The baseline consolidates four useful patterns:

1. **Nancy-style bounded authoring** — untrusted source material is converted into a constrained intermediate format, parsed and validated deterministically, shown as a diff/draft and published only by a human. Respondent answers do not leave the system for authoring.
2. **Test Generator-style disclosure inventory** — document every broker, underlying model/provider, source category, media flow, embedding provider and third-party output destination separately.
3. **Goodman-style governed generation** — require approved knowledge, source IDs, zero-data-retention routing, preservation of numbers/units/qualifiers, render-only exclusion of contacts/commercial values and human approval before final artefact creation.
4. **Petyr-style deterministic authority** — official numeric calculations remain local and deterministic; the LLM may interpret bounded evidence but cannot invent or overwrite authoritative values.

Projects select and adapt a profile; they do not copy every pattern indiscriminately.
