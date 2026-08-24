# Privacy and Telemetry

## Data minimization

Telemetry records only what is necessary for operations, adoption, security or approved evaluation. Business content is excluded by default.

## Storage separation

| Store | Purpose | Identity level |
|---|---|---|
| Metrics | Aggregated technical signals | no user identity |
| Traces | Request diagnostics | pseudonymous or no actor; content omitted |
| Logs | Operational and security diagnostics | bounded subject/correlation where justified |
| Product events | Usage and outcomes | pseudonymous actor |
| Audit | Security-relevant actions | identifiable under restricted access |

## Forbidden metric labels

- email;
- user ID;
- Google subject;
- session ID;
- client secret;
- token ID when unbounded;
- URL query string;
- document or job ID when unbounded.

## AI content

Prompt and output capture is disabled. Any temporary diagnostic capture requires:

- explicit incident scope;
- legal/privacy approval;
- redaction;
- restricted access;
- short retention;
- automatic expiry;
- an audit record.

It is not a normal product setting.
