# Step 4B hardening package

Questo file e autosufficiente: puo essere allegato da solo a una nuova task Codex.

## Prompt operativo

Esegui l'hardening dello Step 4B nel repository `AccessLayervNext`.

Leggi e rispetta integralmente `AGENTS.md` e l'ordine delle fonti richiesto. Non contattare produzione, Coolify, Google reale o database esterni. Usa esclusivamente dati sintetici e due PostgreSQL 16 locali, isolati e usa-e-getta. OAuth deve restare default-off.

Non modificare le migration `001`-`005`, non creare migration `006`, non alterare il frozen legacy baseline e non procedere allo Step 5.

### Baseline ed evidenze dell'audit indipendente

- Step 4A approvato: `1757a40c6369be59427da6618fa8126605a51550`.
- Commit auditato: `2ff5d226b186afd75a79aa4010d7e656f82213e7`.
- Legacy baseline: `access-layer-v1-baseline`, commit `6e8221ade74591c23c3f9606f7d696ea2810d873`.
- Il worktree era pulito e il runner ha qualificato l'esatto commit.
- Sono state eseguite cinque qualifiche sul medesimo commit: quattro `FAIL` e una `PASS` completa.
- Nei quattro fallimenti, le due richieste concorrenti sono terminate entro il timeout e una sola ha restituito HTTP 200; il perdente non ha restituito l'obbligatorio HTTP 400 `invalid_grant`.
- L'unico run completo ha superato OAuth E2E, claims/TTL/JWKS, introspection/revocation, replay, snapshot coordinato, backup cifrato, replace restore, continuita post-restore e smoke legacy health/JWKS/auth-start.
- L'esito variabile sullo stesso commit dimostra una race non deterministica: Step 4B resta `FAIL - BLOCKED_IMPLEMENTATION`.
- Il run completo ha inoltre emesso la warning di `pg`: `Calling client.query() when the client is already executing a query is deprecated and will be removed in pg@9.0`.
- Il cleanup ha lasciato zero container Step 4B e il worktree e rimasto pulito.

### Ipotesi primaria da verificare

In `src/oauth/token-service.ts`, `OAuthTokenLifecycleService.refresh()` acquisisce `now` prima di aprire la transazione e prima dell'attesa sul lock del refresh token.

Una possibile interleaving e:

1. la richiesta A acquisisce un timestamp precedente;
2. la richiesta B acquisisce un timestamp successivo ma vince la gara sul lock;
3. B consuma la generazione 0 e crea la generazione 1 con `issued_at` basato sul proprio timestamp;
4. A riprende, rileva il token consumato e chiama `revokeRefreshReplay()` usando il timestamp precedente;
5. `revokeFamilyAndSession()` tenta di impostare `revoked_at` sulla generazione 1;
6. puo essere violato `oauth_refresh_tokens_revoked_order`, che richiede `revoked_at >= issued_at`;
7. l'errore PostgreSQL viene normalizzato come `temporarily_unavailable` invece dell'obbligatorio `invalid_grant`.

Questa e un'ipotesi evidence-backed, non una conclusione da assumere senza prova. Prima della correzione, confermala o confutala raccogliendo soltanto diagnostica sanitizzata.

### Diagnostica obbligatoria prima della correzione

Estendi l'harness senza indebolirne le asserzioni:

- registra per entrambe le risposte concorrenti soltanto status HTTP e codice OAuth normalizzato;
- registra, quando disponibile, soltanto SQLSTATE, nome del constraint e query-tag sanitizzato;
- non registrare body arbitrari, authorization header, code, access/refresh token, hash di token, credenziali, cookie, chiavi o path privati;
- dopo entrambe le risposte, raccogli lo stato sanitizzato di family, session e lineage anche quando il controllo HTTP fallisce;
- termina comunque con FAIL se non si ottengono esattamente un HTTP 200 e un HTTP 400 `invalid_grant`;
- distingui esplicitamente timeout, deadlock, rate limit, constraint failure e altri errori infrastrutturali.

### Correzione richiesta

Implementa la correzione minima che rispetti i contratti esistenti:

- conserva la serializzazione PostgreSQL e il replay atomico;
- usa un tempo di revoca monotono e semanticamente corretto, stabilito dopo la serializzazione necessaria;
- non rimuovere, disabilitare o indebolire i constraint;
- non convertire genericamente errori DB in `invalid_grant`;
- il replay deve committare revoca della famiglia, sessione, token corrente, durable revocations e audit prima di restituire `invalid_grant`;
- preserva TTL, scope, audience, entitlement, lineage, signing-key e revocation semantics;
- preserva OAuth default-off e tutto il comportamento legacy congelato;
- nessuna modifica alle migration `001`-`005` e nessuna migration `006`.

Elimina inoltre la warning di `pg` prodotta da `Repositories.exportBackup()`: le 24 `SELECT` non devono essere lanciate concorrentemente sullo stesso client. Devono restare tutte nella medesima transazione `REPEATABLE READ, READ ONLY`, mantenendo ordine deterministico e prova anti-torn-snapshot.

### Test obbligatori

1. Aggiungi una regressione deterministica che forzi una richiesta con timestamp precedente a perdere il lock dopo che l'altra richiesta ha creato la generazione successiva.
2. Mantieni test di servizio con clock controllabile, ma non considerarli sostitutivi della prova PostgreSQL reale.
3. Sul PostgreSQL reale, richiedi sempre:
   - esattamente un HTTP 200;
   - esattamente un HTTP 400 `{ "error": "invalid_grant" }`;
   - zero HTTP 429/500/503;
   - zero timeout e zero deadlock;
   - famiglia e sessione `revoked`;
   - `replay_detected_at` valorizzato;
   - generazione 0 `consumed` e generazione 1 `revoked`;
   - parent lineage coerente;
   - access token emesso dal vincitore inattivo tramite introspection online.
4. Aggiungi una ripetizione/stress bounded della race reale, oltre all'interleaving deterministico.
5. Verifica che l'export non emetta piu la deprecation warning di `pg` e conservi un unico snapshot coerente.
6. Mantieni lo smoke del vecchio runtime sulla schema `001`-`005` per `/health`, `/v1/.well-known/jwks.json` e `/v1/auth/start`.

### File da esaminare

- `AGENTS.md`
- `CURRENT_STATE.md`
- `BACKLOG.md`
- `DECISIONS.md`
- `docs/SECURITY.md`
- `docs/TESTING.md`
- `docs/OAUTH_P0_CONTRACT.md`
- `specs/oauth-p0.v1.yml`
- `specs/policy.v1.yml`
- `specs/permissions.v1.yml`
- `specs/visibility.v1.yml`
- `src/oauth/token-service.ts`
- `src/oauth/token-repository.ts`
- `src/oauth/token-http.ts`
- `src/db.ts`
- `src/repositories.ts`
- `migrations/005_oauth_token_lifecycle.sql`
- `tests/oauth-token-lifecycle.test.ts`
- `tests/backup-repositories.test.ts`
- `scripts/step4b/qualify.ts`
- `scripts/step4b/run-qualification.ps1`
- `operations/STEP_4B_QUALIFICATION_REPORT.md`

### Validazione completa

Da un nuovo commit esatto e con worktree interamente pulito, esegui:

- `npm run lint`;
- `npm run build`;
- suite Vitest completa;
- suite Python completa;
- validator OAuth P0, 24/24 gruppi;
- production continuity validator, che deve restare nell'atteso `VALID_BUT_NOT_READY` con exit code 2;
- platform checker non-strict;
- `git diff --check`;
- Step 4B completo su due PostgreSQL 16 distinti e loopback-only.

Per chiudere la flakiness, richiedi almeno tre qualifiche Step 4B complete e consecutive sullo stesso nuovo commit pulito. Ogni qualifica deve ripartire da container e database vuoti, applicare esattamente le migration `001`-`005` e completare tutte le sezioni:

- authorize e callback con solo il boundary Google fake;
- code exchange;
- claims, TTL, OAuth JWKS e introspection;
- refresh e revocation normali;
- race/replay sullo stesso refresh;
- snapshot coordinato repeatable-read;
- backup cifrato e replace restore sul secondo PostgreSQL;
- continuita del token di accesso e del refresh pre-backup;
- smoke del runtime legacy sulla schema espansa.

Ogni run deve terminare senza deprecation warning e lasciare zero container residui.

### Documentazione e consegna

Aggiorna, secondo `AGENTS.md`:

- `DEVLOG.md`;
- `CURRENT_STATE.md`;
- `BACKLOG.md`;
- `docs/TESTING.md`;
- `operations/STEP_4B_QUALIFICATION_REPORT.md`.

Preserva lo storico dei fallimenti: non riscriverlo come se non fosse avvenuto. Registra commit esatto, numero di run, versione PostgreSQL, esiti sanitizzati, cleanup e risultati dei validator.

Non creare il branch `step-4b-completed`, non abilitare OAuth, non effettuare deploy e non procedere allo Step 5. Dopo l'hardening e necessaria una nuova approvazione tramite audit indipendente.

## Riferimenti puntuali dell'audit

- Timestamp pre-lock: `src/oauth/token-service.ts`, circa linea 218.
- Replay call: `src/oauth/token-service.ts`, circa linea 227.
- Revoca del token corrente: `src/oauth/token-repository.ts`, circa linee 572-574.
- Constraint temporale: `migrations/005_oauth_token_lifecycle.sql`, circa linea 100.
- Assertion concorrente: `scripts/step4b/qualify.ts`, circa linee 585-612.
- Query concorrenti del backup: `src/repositories.ts`, circa linea 1171.

## Risultati ordinari dell'audit da preservare

- `npm run lint`: PASS.
- `npm run build`: PASS.
- Vitest: 316 test PASS in 18 file.
- Python unittest: 61 PASS e 2 skip attesi, 63 raccolti.
- OAuth P0 validator: PASS, 24 gruppi.
- Production continuity: atteso `VALID_BUT_NOT_READY`, entrambi i gate false, exit code 2.
- Platform checker non-strict: PASS, 27 check e 7 warning noti.
- `git diff --check`: PASS.
- Migration `001`-`005`: hash congelati invariati.
- Cleanup Docker: PASS, zero container Step 4B residui.
- Stato finale dell'audit: `FAIL - BLOCKED_IMPLEMENTATION`.
