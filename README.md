# Access Layer Google SSO

> Platform status (2026-08-25): Template v2.1 is adopted in `legacy-migration` mode. Live evidence resolved the source Compose PostgreSQL logical-volume mismatch without renaming the live volume. Deployment remains blocked by the backup/restore, ownership, registry and remaining continuity gates in `BACKLOG.md`.

> OAuth vNext status: Step 3D adds a default-off, unmounted token-lifecycle core beside the frozen Step 3B/3C surfaces. With `OAUTH_P0_ENABLED` absent/false every new route remains 404; even when true, RFC 8414, token, revoke and introspect remain unregistered. No pilot, production key/secret or enablement exists, and `specs/oauth-p0.v1.yml` remains frozen.

Layer di accesso condiviso per tool web interni aziendali.

Il servizio centralizza autenticazione, autorizzazione e audit trail per tutti i tool interni. Gli utenti accedono con account Google aziendale; il layer verifica che l'identita appartenga al dominio Google Workspace aziendale, controlla se l'utente e autorizzato al tool richiesto, registra il tentativo di accesso e rilascia al tool una identita verificata.

## Obiettivo

- Identificare chi accede a ogni tool interno.
- Bloccare account esterni o non appartenenti al dominio Workspace aziendale.
- Permettere agli admin di autorizzare utenti e ruoli per ciascun tool.
- Fornire un contratto API standard per tool esistenti e futuri.
- Produrre log di accesso sicuri, interrogabili e non basati su dati non verificati.

## Flusso sintetico

1. Il tool reindirizza l'utente a `GET /v1/auth/start` in produzione, o a `GET /access-control/v1/auth/start` in locale, passando `tool_slug`, `return_url` e uno `state` generato dal tool.
2. Access Layer registra la richiesta, avvia il login Google OpenID Connect e mantiene una correlazione sicura.
3. Dopo il callback Google, Access Layer valida ID token, `aud`, `iss`, `exp`, `email_verified` e `hd`.
4. Se l'utente e autorizzato al tool, Access Layer genera un one-time code e reindirizza al callback del tool.
5. Il backend del tool scambia il one-time code con `POST /v1/auth/exchange` in produzione, o `POST /access-control/v1/auth/exchange` in locale, autenticandosi come tool client.
6. Il tool riceve identita, permessi e token firmato da Access Layer, crea la propria sessione locale e logga il `sub` Google e `session_id`.
7. Durante una richiesta autenticata, quando il JWT sta per scadere, il backend del tool ruota il refresh token tramite `POST /v1/auth/refresh`; ogni refresh valido estende la scadenza inattiva della sessione.

## Stack di riferimento

La specifica API e indipendente dallo stack dei tool. Per implementare il servizio Access Layer, questo pacchetto propone come default:

- Node.js 22 LTS + TypeScript
- Fastify o Express
- PostgreSQL
- migrazioni SQL esplicite con driver `pg`
- `google-auth-library` per validare ID token Google
- `jose` per firmare/verificare JWT interni
- OpenAPI 3.1 come contratto API

Lo stack puo essere cambiato, ma la modifica va registrata in `DECISIONS.md` e deve preservare API, sicurezza, audit e integrazione.

## Produzione Coolify

Il pacchetto e predisposto per Coolify in produzione su `https://access-layer.unguess-internal.net`, senza base path pubblico. Le variabili reali vanno inserite nella UI di Coolify, partendo da `.env.production.example`; non caricare file `.env` con segreti nello zip/repository.

Leggere `COOLIFY.md` prima del deploy.

## Avvio locale con Docker

Il repository include un profilo Docker Compose per avviare Access Layer e PostgreSQL insieme.

1. Copiare l'esempio Docker:

   ```bash
   cp .env.docker.example .env.docker
   ```

2. Aggiornare in `.env.docker` almeno:

   - `POSTGRES_PASSWORD` e la password corrispondente dentro `DATABASE_URL`;
   - `GOOGLE_CLIENT_ID`;
   - `GOOGLE_CLIENT_SECRET`;
   - `ADMIN_BOOTSTRAP_EMAILS`;
   - `SESSION_SECRET`, `TOOL_CLIENT_SECRET_PEPPER`, `LOG_IP_SALT`.

3. Avviare stack e database usando lo script npm, che passa `.env.docker` a Docker Compose:

   ```bash
   npm run docker:up
   ```

Il compose espone Access Layer su `http://localhost:8080`; PostgreSQL resta sul network Docker interno. La root locale `/` rimanda alla Admin UI `/access-control`. All'avvio dell'app containerizzata vengono eseguite le migrazioni; per sviluppo locale viene eseguito anche il seed iniziale. Se il file della chiave JWT non esiste ancora nel volume Docker, l'entrypoint genera una chiave locale senza stamparne il contenuto.

Per fermare lo stack:

```bash
npm run docker:down
```

## File principali

Leggere in questo ordine:

1. `AGENTS.md`
2. `CURRENT_STATE.md`
3. `BACKLOG.md`
4. `DECISIONS.md`
5. `docs/SCOPE.md`
6. `docs/DOMAIN.md`
7. `docs/ARCHITECTURE.md`
8. `docs/SECURITY.md`
9. `docs/API.md`
10. `docs/OAUTH_P0_CONTRACT.md` for target OAuth work
11. `docs/OAUTH_ADDITIVE_DATA_MODEL.md` for target OAuth data design
12. `docs/GOOGLE_CLOUD_SETUP.md`
13. `docs/INTEGRATION_GUIDE.md`
14. `docs/IMPLEMENTATION_PLAN.md`

Per aggiornare un tool gia integrato alla rotazione refresh e alle sessioni sliding, usare `prompts/TOOL_REFRESH_MIGRATION_PROMPT.md`.

## Output atteso dell'implementazione

- Backend API funzionante.
- Database e migrazioni.
- Admin UI minimale per tool, utenti, grant e log.
- Integrazione Google OIDC completa.
- Token interni firmati e JWKS pubblico.
- Audit log strutturati.
- Test automatici per flussi positivi, negazioni e sicurezza.
- Documentazione aggiornata a ogni modifica.

## Non negoziabili

- Mai fidarsi del dominio della mail da solo: validare sempre il claim `hd` dell'ID token Google.
- Mai usare `email` come primary key utente: usare `sub` Google come identificativo stabile.
- Mai mettere token, client secret, authorization code o cookie nei log.
- Ogni tool deve essere registrato con `tool_slug`, credenziali server-to-server e `return_url` allow-listato.
- Ogni tentativo di accesso deve generare un audit event correlabile.
