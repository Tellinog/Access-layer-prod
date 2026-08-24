# AI governance

## Safe default

AI is disabled by default. Setting `AI_ENABLED=true` is not sufficient. The project must also complete and pass the machine-readable and human-readable governance records.

## Profiles

| Profile | Meaning | Default release posture |
|---|---|---|
| `no_ai` | No runtime AI behavior | Allowed after code/dependency scan |
| `assistive_generation` | AI produces an editable draft | Human review required |
| `decision_support` | AI interprets deterministic data | Consultative only; official calculation remains deterministic |
| `autonomous_action` | AI can initiate effects | Explicit security/legal/product approval |
| `high_risk_candidate` | Intended purpose may match a high-risk category | Release blocked pending assessment |
| `prohibited` | Use case may involve a prohibited practice | Development/release blocked |

## Default engineering patterns

### AI-assisted authoring

```text
untrusted document/instruction
-> approved provider/model
-> constrained intermediate format
-> deterministic parser
-> schema and safety validation
-> diff/draft
-> explicit human publication
```

### Controlled content generation

```text
approved/versioned knowledge
-> minimised provider payload
-> source-constrained generation
-> deterministic rendering
-> human review
-> export/delivery
```

### Decision support

```text
deterministic calculation
-> minimised/pseudonymised features
-> AI interpretation
-> strict JSON validation
-> evidence references
-> consultative UI
```

AI must not become the source of truth for official numeric results unless a separate approved risk assessment explicitly permits it.

## Mandatory governance records

- intended purpose and prohibited uses;
- operator-role assessment;
- prohibited-practice screen;
- high-risk/Annex III screen;
- transparency assessment;
- data and model governance;
- provider and subprocessor evidence;
- human oversight;
- evaluation and change control;
- AI literacy;
- incident response.

## Provider gate

A production AI provider/model must have known and approved:

- broker/router and underlying model provider;
- exact model ID and version policy;
- retention;
- training use;
- data region/transfer position;
- DPA/contract status;
- subprocessors;
- allowed data classes;
- owner and review date.

`unknown` is a release-blocking state unless a documented exception is approved.

## Model and prompt changes

A model, provider, router, prompt, schema or retrieval-source change requires:

1. updated registry/version;
2. evaluation comparison;
3. privacy/security/compliance impact check;
4. controlled rollout;
5. rollback plan;
6. changelog and Observatory annotation.

## Output and provenance

AI-assisted outputs include machine-readable provenance appropriate to the medium without exposing prompts, chain of thought, keys or sensitive input.

## Legal note

This repository provides compliance readiness and evidence structure. It does not provide legal advice or automatically determine the project's legal classification.
