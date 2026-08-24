# Language and Localization

## Default

Product UI uses British English (`en-GB`). Technical contracts and documentation use English.

## English-required surfaces

- navigation, labels, buttons and status messages;
- validation and error messages;
- email and notification templates;
- OpenAPI descriptions and examples;
- MCP tool/resource/prompt metadata;
- capability, event and metric names;
- auth consent and access-denied pages;
- monitoring and management dashboards;
- agent instructions and system prompts, unless the use case requires another language.

## User content

Do not translate user-provided content automatically. Store and return it in the original language unless a clearly named translation capability is invoked.

## Generated output

`en-GB` is the default. A capability may accept an explicit output locale when documented and evaluated. Language selection does not silently change timezone, currency, legal jurisdiction or data-retention rules.

## Implementation

- set `<html lang="en-GB">`;
- use `src/locales/en-GB.json` or an equivalent catalogue even with one language;
- identifiers remain stable and untranslated;
- fallback is English;
- backend/provider errors are mapped to safe English application messages;
- avoid anthropomorphism and unsupported claims about AI reasoning.

Preferred:

```text
AI-assisted draft. Review the content and sources before publishing.
```

Avoid:

```text
I carefully analysed all your data and made the best decision.
```
# Access Layer adoption status

The policy below is a future target. The current Admin UI and safe error copy contain Italian text. Step 1 intentionally does not translate or redesign the UI and freezes existing error messages; see `../specs/language.v1.yml`.
