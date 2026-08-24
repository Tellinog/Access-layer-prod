# Human Oversight

## Default profile

AI output is a draft. A human with the required capability can:

- inspect input scope and sources;
- review validation warnings and provenance;
- edit the draft;
- reject it;
- regenerate it;
- approve it;
- undo or supersede it where the domain permits.

## Mandatory separation of capabilities

Generation, approval and publication/external delivery are distinct operations and permissions.

```text
generate_draft -> review -> approve -> publish/export/send
```

## Actions AI must not perform directly by default

- change Access Layer permissions, OAuth clients, scopes or callbacks;
- publish or send externally;
- delete data;
- change official numeric results;
- make employment, eligibility or other high-impact decisions;
- approve commercial values;
- modify immutable records;
- select an unapproved provider/model;
- bypass human confirmation through API or MCP.

## Effective oversight

The reviewer must receive enough information and time to intervene. A checkbox without meaningful ability to understand, reject or correct the output is not sufficient.

## Agent channels

MCP/API capability policy must enforce the approval boundary. An agent cannot call a hidden `publish` path merely because the web UI normally asks for confirmation.
