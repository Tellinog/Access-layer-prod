# AI Incident Response

## Incident triggers

- sensitive data sent outside the approved boundary;
- generated content published without required disclosure or approval;
- materially false/unsupported output with user or client impact;
- model/provider changed without review;
- prompt injection caused unauthorized action or disclosure;
- systematic bias or high-risk use outside intended purpose;
- provider retention/training behavior changed;
- provenance or machine-readable marking failed;
- human oversight could not intervene.

## Immediate actions

1. Disable the specific AI capability/provider/model through a feature flag.
2. Preserve deterministic/manual functionality.
3. Stop further external transmission.
4. Record correlation, trace, capability, model and release metadata without expanding sensitive-content capture.
5. Notify security, product, privacy/legal and the named AI owner according to severity.
6. Preserve approved evidence and assess notification duties.

## Recovery

- correct data or provider boundary;
- rerun evaluation;
- document root cause and affected artefacts;
- issue correction/retraction where needed;
- obtain approval before re-enable;
- update training and controls.
