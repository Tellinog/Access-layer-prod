# LOGGING.md

## Temporary legacy Microsoft bridge events

The conditional Microsoft callback emits `microsoft.callback.received` and then the same existing `auth.allowed`/`auth.denied.*`, session and exchange events as Google. Provider selection denials use the existing safe audit envelope with the new reason codes. `actor_google_sub` remains the frozen field name and may contain the approved synthetic `msft:<tid>:<oid>` value for this bridge.

Automatic request logging is silent on `/v1/auth/microsoft/callback`. Never log Microsoft authorization codes, ID/access tokens, raw token responses, nonce/state, `error_description`, client secret, UPN beyond the already allowed normalized actor email, or arbitrary claim payloads. Safe Microsoft metadata is limited to correlation ID, tool identity, outcome/reason and the already approved actor fields after validation.

## Obiettivo

Access Layer deve sapere da chi arriva ogni richiesta di accesso, per quale tool, e con quale risultato.

## Eventi obbligatori

| Event type | Quando | Outcome tipico |
|---|---|---|
| `auth.requested` | Un tool chiama `/v1/auth/start` in produzione, o il path equivalente sotto il base path locale | `info` |
| `auth.denied.invalid_tool` | `tool_slug` inesistente o disabilitato | `denied` |
| `auth.denied.invalid_return_url` | `return_url` non allow-listato | `denied` |
| `auth.denied.invalid_state` | `state` mancante, malformato, scaduto o gia consumato | `denied` |
| `google.callback.received` | Google ritorna al callback | `info` |
| `microsoft.callback.received` | Microsoft Entra ritorna al callback legacy condizionale | `info` |
| `auth.denied.invalid_google_token` | ID token non valido | `denied` |
| `auth.denied.external_domain` | `hd` mancante o non ammesso | `denied` |
| `auth.denied.email_not_verified` | `email_verified=false` | `denied` |
| `auth.denied.user_disabled` | utente disabilitato | `denied` |
| `auth.denied.no_grant` | nessun grant attivo per tool | `denied` |
| `access_request.created` | utente aziendale valido senza grant genera richiesta admin | `info` |
| `access_request.repeated` | stesso utente/tool riprova mentre richiesta e pendente | `info` |
| `access_request.reopen_suppressed` | nuovo tentativo dopo rifiuto/chiusura recente prima della finestra di riapertura | `info` |
| `auth.allowed` | utente autorizzato al tool | `success` |
| `token.exchanged` | tool consuma one-time code | `success` |
| `token.exchange.denied` | exchange fallito | `denied` |
| `token.refreshed` | refresh activity-driven riuscito, token ruotato e sessione estesa | `success` |
| `token.refresh.denied` | refresh non valido, scaduto, riutilizzato o non piu autorizzato | `denied` |
| `auth.denied.token_in_query` | token-like credential ricevuta nella query string | `denied` |
| `token.introspected` | tool chiama introspection | `info` |
| `session.revoked` | sessione revocata | `success` |
| `session.revoke.denied` | richiesta logout/revoca non autenticata o non valida | `denied` |
| `admin.tool.created` | admin crea tool | `success` |
| `admin.tool.updated` | admin aggiorna tool | `success` |
| `admin.tool.secret_rotated` | admin ruota secret | `success` |
| `admin.grant.created` | admin crea grant | `success` |
| `admin.grant.updated` | admin aggiorna ruolo, permessi o validita grant | `success` |
| `admin.access_request.approved` | admin approva richiesta accesso | `success` |
| `admin.access_request.rejected` | admin rifiuta richiesta accesso | `success` |
| `admin.access_request.closed` | admin chiude richiesta senza grant | `success` |
| `admin.grant.revoked` | admin revoca grant | `success` |
| `admin.user.status_changed` | admin cambia stato utente | `success` |

OAuth vNext target events:

| Event type | Purpose |
|---|---|
| `oauth.authorization.requested` / `allowed` / `denied` | Correlate P0 authorization decisions without logging request credentials |
| `oauth.code.issued` / `exchanged` / `exchange_denied` | Record code lifecycle without the code or PKCE verifier |
| `oauth.token.refreshed` | Record activity-driven family rotation |
| `oauth.refresh.replay_detected` | High-signal replay event with family/session revocation outcome |
| `oauth.token.revoked` / `introspected` | Record revocation and authorised online validation without raw tokens or inactive reason leakage |
| `oauth.client.changed` / `oauth.resource.changed` / `oauth.scope.changed` | Record controlled registration changes |
| `oauth.signing_key.changed` | Record public `kid` lifecycle action without private key material |

Step 3C HTTP emits `oauth.authorization.requested`, `oauth.authorization.allowed`, `oauth.authorization.denied` and `oauth.code.issued`. Step 3D services add transaction-bound `oauth.code.exchanged`, `oauth.token.refreshed`, `oauth.refresh.replay_detected`, `oauth.token.revoked` and `oauth.token.introspected`; Step 3E mounts those service paths without changing audit payloads. Failed code exchange writes sanitized `oauth.code.exchange_denied` in a deliberately separate bounded transaction after the failed main transaction rolls back. If this mandatory denial audit write fails, the operation remains denied and surfaces only `temporarily_unavailable`. D-047 now emits stable transaction-bound `oauth.client.changed`, `oauth.resource.changed`, `oauth.scope.changed` and `oauth.signing_key.changed` events for Admin mutations. Automatic Fastify request logs stay silent on secret-producing OAuth Admin mutations and on `/oauth/authorize`, `/oauth/upstream/google/callback`, `/oauth/token`, `/oauth/revoke` and `/oauth/introspect`.

OAuth audit metadata may contain client ID, exact resource ID, canonical scope IDs, stable Google subject/user ID when known, correlation ID, outcome and non-sensitive reason code. It must not contain authorization or Google codes, tokens, client secrets, cookies, PKCE verifiers/challenges, downstream/upstream state, nonce, private keys, secret hashes/verifiers, raw query strings or raw form bodies.

## Campi comuni

| Field | Required | Notes |
|---|---:|---|
| `event_id` | yes | ULID/UUID |
| `created_at` | yes | UTC ISO-8601 |
| `event_type` | yes | Valore enumerato |
| `outcome` | yes | `success`, `denied`, `error`, `info` |
| `correlation_id` | yes | Stesso ID lungo tutto il flow |
| `tool_slug` | when known | Richiesta accesso per tool |
| `actor_google_sub` | when known | Dopo validazione Google |
| `actor_email` | when known | Email corrente da Google |
| `actor_hd` | when known | Hosted domain validato |
| `request_ip_hash` | recommended | Salted hash, non raw IP di default |
| `user_agent_hash` | recommended | Salted hash |
| `reason_code` | yes for denied/error | Codice stabile |
| `metadata` | optional | Solo dati non sensibili |

## Dati vietati nei log

- Google authorization code.
- Google ID token.
- Access Layer access token.
- Refresh token.
- Cookie sessione.
- Client secret.
- Password o credenziali.
- Raw request body se contiene segreti.
- Dati business sensibili del tool.

## IP e privacy

Default v1:

- salvare hash IP con salt segreto `LOG_IP_SALT`;
- non salvare raw IP se `AUDIT_LOG_RAW_IP=false`;
- conservare raw IP solo se serve per obblighi di sicurezza/compliance e se approvato.

## Correlation ID

Il `correlation_id` viene creato all'inizio del flow e propagato in:

- auth request record;
- Google callback processing;
- access decision;
- one-time code;
- token exchange response;
- tool session/logs.

## Retention

Default: 365 giorni.

Prima della produzione confermare requisiti privacy/compliance aziendali.


## Healthcheck request logs

`GET /health` and, in local base-path deployments, `GET /access-control/health` are operational health probes, not audit events.

Docker Compose probes the app health endpoint every 10 seconds. Successful health probes are intentionally configured with silent route logging so normal application logs remain focused on user, admin, auth and API traffic.
