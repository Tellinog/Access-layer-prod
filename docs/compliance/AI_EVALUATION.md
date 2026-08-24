# AI Evaluation

## Evaluation set

Maintain a versioned, representative and privacy-approved evaluation set for each AI capability.

## Required dimensions as applicable

- schema validity;
- unsupported-claim rate;
- source attribution and source-ID validity;
- numeric/unit/qualifier fidelity;
- deterministic-rule consistency;
- prompt-injection resistance;
- personal-data and secret leakage;
- language quality and locale compliance;
- refusal and policy correctness;
- human acceptance, edit and rejection rates;
- latency, token use and cost;
- provider/model fallback behavior.

## Gates

Define numeric thresholds in `specs/ai-evaluation.v1.yml`. A model change, prompt change or material data-boundary change reruns the relevant suite.

## Production monitoring

Track metadata and human-review outcomes without capturing content. Drift or rising correction/rejection rate triggers investigation and possible kill switch.
