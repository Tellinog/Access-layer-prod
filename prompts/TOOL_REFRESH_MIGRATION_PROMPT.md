# Prompt Codex - migrazione tool ad Access Layer refresh sliding

Copia il testo seguente nella task Codex del repository del tool da aggiornare. Allega anche il pacchetto sorgente aggiornato di Access Layer, oppure fornisci un link/commit leggibile, se quella task non ha accesso a questo repository.

---

Devi aggiornare questo tool per supportare il refresh activity-driven introdotto da Access Layer.

Prima di modificare:

1. leggi integralmente le istruzioni agent/repository locali;
2. individua login, callback, session store, middleware delle route protette, client Access Layer e logout;
3. verifica come vengono conservati oggi `access_token`, identity, permessi, `session.id` e scadenze;
4. non modificare Access Layer: questa task riguarda esclusivamente il tool corrente;
5. se il tool non ha un backend capace di proteggere client secret e refresh token, registra un blocker e non spostare credenziali nel frontend.

## Contratto Access Layer aggiornato

L'exchange esistente `POST /v1/auth/exchange` continua a funzionare e restituisce:

- `access_token`;
- `token_type: "Bearer"`;
- `expires_in` (attualmente 900 secondi);
- `refresh_token`;
- `session.id`, `session.issued_at`, `session.expires_at`;
- `user`, `tool`, `grant`, `correlation_id`.

Il nuovo endpoint è:

```http
POST {ACCESS_LAYER_INTERNAL_BASE_URL}/v1/auth/refresh
Authorization: Basic base64(ACCESS_LAYER_CLIENT_ID:ACCESS_LAYER_CLIENT_SECRET)
Content-Type: application/json

{"refresh_token":"<current-refresh-token>"}
```

Una risposta `200` ha la stessa forma dell'exchange e contiene sempre un nuovo access token e un nuovo refresh token. Il refresh token inviato diventa immediatamente inutilizzabile. Una risposta `401` con `AUTH_REFRESH_TOKEN_INVALID` indica token scaduto/riutilizzato/non valido oppure tool, user, grant o sessione non più attivi.

## Comportamento da implementare

1. Nel callback, salva access token, refresh token, scadenza access token, `session.id`, `session.expires_at`, identity e permessi esclusivamente nella sessione/storage server-side del tool.
2. Non inserire mai refresh token o client secret in JavaScript browser, localStorage, sessionStorage, URL, HTML, log o messaggi di errore.
3. Durante ogni richiesta autenticata dell'utente, prima dell'operazione protetta:
   - leggi la sessione locale;
   - se l'access token ha più di 60 secondi residui, continua normalmente;
   - se è scaduto o ha al massimo 60 secondi residui, esegui un refresh server-to-server;
   - dopo `200`, sostituisci atomicamente access token, refresh token, scadenze, identity e permessi con la nuova risposta;
   - prosegui la richiesta originale una sola volta con lo stato aggiornato.
4. Non creare timer, cron, heartbeat o richieste periodiche in background: una pagina aperta ma inattiva non deve mantenere viva la sessione.
5. Serializza i refresh concorrenti per la stessa sessione locale:
   - deve partire una sola chiamata `/v1/auth/refresh`;
   - le richieste concorrenti attendono il risultato e poi rileggono la sessione aggiornata;
   - non devono usare in parallelo lo stesso refresh token monouso.
6. Su `401 AUTH_REFRESH_TOKEN_INVALID`, errore di rete non recuperabile o risposta refresh malformata:
   - cancella la sessione locale e tutti i token;
   - non riprovare lo stesso refresh token;
   - per una navigazione browser, reindirizza al normale login Access Layer;
   - per una API, restituisci la risposta di autenticazione prevista dal tool, senza esporre dettagli o token.
7. Nel logout:
   - chiama `POST /v1/auth/logout` con Basic Auth;
   - invia sia `session_id` sia l'ultimo `refresh_token`, se disponibili;
   - cancella sempre la sessione/cookie locale anche se il logout remoto fallisce;
   - non loggare i valori inviati.
8. Usa `ACCESS_LAYER_INTERNAL_BASE_URL` per exchange, refresh, introspection e logout. Usa `ACCESS_LAYER_PUBLIC_BASE_URL` solo per il redirect browser al login.
   - preserva l'eventuale base path, per esempio `/access-control`; non costruire URL in modo che un path assoluto elimini il base path configurato;
9. Mantieni invariati mapping di ruoli/permessi e validazione JWT, salvo gli adeguamenti necessari a usare i valori aggiornati dopo il refresh.

## Semantica sessione

- Access token: 15 minuti.
- Timeout di inattività: 8 ore.
- Ogni refresh valido causato da attività utente sposta in avanti di 8 ore `session.expires_at`.
- Finché arrivano richieste utente e i controlli centrali restano validi, la sessione continua.
- Dopo 8 ore senza refresh valido serve un nuovo login.

## Test obbligatori

Aggiungi o aggiorna test per:

1. callback che conserva refresh token e scadenze solo server-side;
2. richiesta con access token ancora valido, senza refresh;
3. richiesta con token vicino alla scadenza, refresh riuscito e richiesta originale completata;
4. rotazione: il nuovo refresh token sostituisce il precedente;
5. due richieste concorrenti producono una sola chiamata refresh;
6. `AUTH_REFRESH_TOKEN_INVALID` cancella la sessione e avvia il login/ritorna una risposta non autenticata;
7. assenza di refresh in background;
8. logout che invia ultimo refresh token e session ID e pulisce la sessione locale;
9. nessun token/client secret nei log o nelle risposte browser;
10. compatibilità con il base path e con la separazione URL pubblico/interno già configurata.

Aggiorna documentazione, env example e test del tool solo dove necessario. Esegui lint, typecheck/build e test pertinenti. Nel riepilogo finale indica file modificati, comportamento, verifiche eseguite e qualsiasi blocker.

---

## Materiale di riferimento consigliato

Se possibile, fornisci alla task Codex anche questi file della nuova versione Access Layer:

- `schemas/openapi.yaml`;
- `docs/API_PAYLOADS.md`;
- `docs/INTEGRATION_GUIDE.md`;
- `docs/SECURITY.md`;
- `specs/policy.v1.yml`;
- `examples/tool-harness/server.mjs`.

Il repository/pacchetto completo è utile quando il tool ha un'integrazione non standard. Non includere `.env` reali, chiavi, secret, `.git`, `node_modules` o `dist`.
