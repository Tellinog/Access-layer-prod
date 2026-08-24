# Consumer Compatibility Matrix

The consumer repositories were inspected read-only from the supplied archives. No consumer or SDK file was changed. Because four consumer archive checksums differ from the instruction pack, this is compatibility evidence for the supplied files, not proof of the pack's referenced revisions.

| Consumer | Registration evidence | Access Layer calls | Session/refresh behavior | Validation | Compatibility findings |
|---|---|---|---|---|---|
| Nancy | tool `community-forms`; permission `community-forms:access`; local callback `http://localhost:3120/auth/callback`; production callback unresolved | start, exchange, refresh, introspect, logout | encrypted server session; opaque cookie; refresh 30s before expiry; in-memory per-session lock; introspects each request | RS256 JWT issuer/audience and `sub`, `sid`, `tool_slug`, `permissions` | Compatible with frozen v1 by repository evidence; multi-replica refresh coordination is not proven; production callback must be verified |
| Test Generator | tool `test-generator`; callback `https://test-generator.unguess-internal.net/auth/access-layer/callback`; permissions `test-generator:access`, `test-generator:admin` | start, exchange, refresh, introspect, logout | encrypted PostgreSQL session; `tg_session` cookie; refresh threshold 60s; persistent reload plus in-memory lock; introspection interval 300s | RS256 issuer/audience and claims consistency | Compatible with frozen v1 by repository evidence; live registration and multi-replica rotation are not proven |
| Goodman | tool `sales-deck-agent`; callback `https://goodman.unguess-internal.net/auth/callback`; permissions `sales-deck:use`, `sales-deck:manage-knowledge` | start, exchange, refresh, logout | encrypted SQLite session; opaque `unguess_deck_session` cookie; refresh threshold 60s; in-memory coordinator | no introspection or local JWKS/JWT verification observed | Core flow matches frozen v1; revocation awareness depends on refresh/request behavior; multi-replica coordination not proven |
| Petyr web | tool `petyr`; callback `https://petyr.unguess-internal.net/auth/callback`; registered read/forecast-write/management-write/admin permissions | start, exchange, logout | signed cookie containing identity, permissions and session ID; 8h max age; no refresh token retained | no introspection or JWT/JWKS verification observed | Uses superseded Access Layer origin `https://access-layer.draftapps.it`; code references `petyr:redash:operator` absent from supplied registration; cannot preserve refresh rotation or promptly observe revocation |
| Petyr Redash ingestor | tool `redash-ingestor`; callback `https://petyr.unguess-internal.net/redash-ingestor/auth/callback`; read/sync/sources-write/admin permissions | start, exchange, logout | same signed-cookie pattern; no refresh token retained | no introspection or JWT/JWKS verification observed | Uses superseded Access Layer origin; refresh/session survival and prompt revocation handling are not implemented in supplied evidence |

## Cross-consumer conclusions

- The frozen response retains fields all supplied consumers rely on.
- Nancy and Test Generator consume refresh/introspection and are the strongest candidates for the future survival harness.
- Goodman refreshes but does not introspect or locally verify JWTs.
- Petyr has known origin and permission-registration drift and does not retain refresh credentials.
- In-memory refresh locks are not evidence of safe single-use rotation across multiple replicas.
- Live tool registrations, secrets, callbacks and deployed image versions were not available; no end-to-end compatibility pass is claimed.

## Archive provenance

| Archive | SHA-256 observed | Pack comparison |
|---|---|---|
| Agent Ready Project Template v2.1.0 | `3e5a00571cca75f0e0e724a332b4603241337fd03a76b24ecd6dc8377146d40c` | Match |
| UNGUESS SDK Phase 3 | `2e24fe34fb75a1cb39c14004bb219aa1368874fd6eaeb287de14adf7d30a91df` | Match |
| Access Layer production | `17ff1d5c903daad47a7c118122084b67f49b25b5e06c6108b8cc43ffa15f3249` | Mismatch |
| Nancy | `dc2601cd5049060003c0c0a6578e16ec2df0a7bc9ed0da62ac80e58fbaa2403d` | Mismatch |
| Test Generator | `791bd254811cf5b2f65e72af636c781f97f1fa21100a37e1663a6c4d2c3cbdd5` | Mismatch |
| Goodman | `ee9d9c59d3493471764f59c0e4b6eb602e2e062e57b4d4d6329aaec9b660d6c7` | Mismatch |
| Petyr | `de0671645d33591d244834491b9018982bffe58d685d43ab600024b23031f586` | Mismatch |
