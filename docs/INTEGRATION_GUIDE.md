# INTEGRATION_GUIDE.md

Guida per integrare Access Layer in tool esistenti o futuri.

## Requisiti del tool

Ogni tool deve avere:

- un backend server-side;
- una route di login;
- una route callback;
- possibilita di conservare un client secret in modo sicuro;
- una sessione locale o middleware API;
- log applicativi capaci di includere `google_sub`, `email`, `tool_slug`, `access_session_id`, `correlation_id`.

Frontend-only tools must add a backend proxy. A tool client secret must never be stored in browser code.

## 1. Registrare il tool in Access Layer

Admin crea un tool con:

- `slug`: esempio `crm`;
- `display_name`: esempio `CRM interno`;
- `allowed_return_urls`: esempio `https://crm.draftapps.it/auth/callback`;
- `status`: `active`;
- eventuali permission keys del tool.

Access Layer genera:

- `tool_client_id`;
- `tool_client_secret` mostrato una sola volta.

Il tool salva questi valori nel proprio secret manager o env.

Se il tool usa permessi granulari, le permission keys devono essere registrate in Access Layer prima di creare grant che le usano.

## 2. Aggiungere env al tool

```env
ACCESS_LAYER_BASE_URL=https://access-layer.draftapps.it
ACCESS_LAYER_TOOL_SLUG=crm
ACCESS_LAYER_CLIENT_ID=tool_client_id
ACCESS_LAYER_CLIENT_SECRET=tool_client_secret
ACCESS_LAYER_CALLBACK_URL=https://crm.draftapps.it/auth/callback
ACCESS_LAYER_JWKS_URL=https://access-layer.draftapps.it/v1/.well-known/jwks.json
```

## 3. Login route del tool

Quando l'utente apre una pagina protetta senza sessione locale, il tool deve generare uno state casuale, salvarlo nella sessione temporanea e reindirizzare a:

```text
GET {ACCESS_LAYER_BASE_URL}/v1/auth/start?tool_slug={slug}&return_url={callback_url}&state={state}
```

Regole:

- usare solo HTTPS in produzione;
- generare `state` almeno 128 bit casuali;
- scadere lo state entro pochi minuti;
- non includere segreti nello state.

## 4. Callback route del tool

La route callback riceve:

```text
GET /auth/callback?code=<one-time-code>&state=<same-state>
```

Il tool deve:

1. verificare che `state` corrisponda a quello salvato localmente;
2. inviare `code` al backend Access Layer con `POST {ACCESS_LAYER_BASE_URL}/v1/auth/exchange`;
3. autenticarsi con Basic Auth usando tool client ID/secret;
4. ricevere identity, grant e access token;
5. creare sessione locale tool-scoped;
6. eliminare state temporaneo;
7. loggare accesso locale con `correlation_id` ricevuto.

## 5. Middleware per richieste protette

Per ogni richiesta autenticata nel tool:

- verificare sessione locale;
- leggere identity salvata: `google_sub`, `email`, `hd`, `permissions`;
- se si usa JWT Access Layer, verificare firma, issuer, audience, expiration e session ID;
- per controlli online/revoca, chiamare `{ACCESS_LAYER_BASE_URL}/v1/auth/introspect`;
- applicare permessi tool-specifici.

## 6. Uso del JWT Access Layer

Il JWT e tool-scoped. Un tool deve accettarlo solo se:

- firma valida con JWKS Access Layer;
- `iss` uguale a `AUTH_ISSUER`;
- `aud` uguale al proprio `tool_slug` o client ID;
- `exp` non scaduto;
- `session_id` presente;
- `google_sub` presente;
- permessi coerenti con il tool.

## 7. Logout

Il tool deve:

1. cancellare la sessione locale;
2. chiamare `POST {ACCESS_LAYER_BASE_URL}/v1/auth/logout` se possiede session ID o refresh token Access Layer;
3. redirigere l'utente a una pagina neutra.

Logout dal tool non deve necessariamente fare logout globale da Google.

## 8. Logging minimo nel tool

Ogni tool deve aggiungere ai propri log applicativi:

- `tool_slug`;
- `google_sub`;
- `email`;
- `access_session_id`;
- `correlation_id`;
- `action` applicativa;
- `outcome`.

Non loggare:

- authorization code;
- access token;
- refresh token;
- cookie sessione;
- client secret;
- payload sensibili del business tool.

## 9. Error handling UX

Il tool deve gestire errori di callback:

- `access_denied`: mostrare messaggio generico e link a supporto.
- `invalid_state`: cancellare sessione temporanea e far ripartire login.
- `tool_disabled`: mostrare manutenzione o contattare admin.
- `not_authorized`: non riprovare in loop; mostrare istruzione di richiesta accesso.

## 10. Migrazione tool esistente

Checklist:

- [ ] Registrare tool in Access Layer.
- [ ] Aggiungere env segreti.
- [ ] Creare login route.
- [ ] Creare callback route.
- [ ] Implementare exchange server-to-server.
- [ ] Mappare `permissions` Access Layer a ruoli locali.
- [ ] Aggiornare log locali con campi identita.
- [ ] Disabilitare vecchi login esterni non aziendali.
- [ ] Testare utente autorizzato, non autorizzato, esterno, return URL invalido.

## 11. Harness di esempio

Un harness minimale senza framework e disponibile in `examples/tool-harness/`.

Usarlo per verificare un tool pilota in locale:

1. registrare il tool `crm` o equivalente in Access Layer;
2. configurare le variabili `ACCESS_LAYER_*` descritte nel README del harness;
3. avviare Access Layer e poi `node examples/tool-harness/server.mjs`;
4. aprire `http://localhost:3000` e completare il flusso login/callback/exchange/logout.

Il harness non logga codici, token, cookie o client secret.
