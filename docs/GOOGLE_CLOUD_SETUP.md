# GOOGLE_CLOUD_SETUP.md

Guida passo passo per creare il progetto Google e ottenere le chiavi necessarie.

Fonti ufficiali utili:

- Google Auth Platform overview: https://support.google.com/cloud/answer/15544987?hl=en
- Manage App Audience: https://support.google.com/cloud/answer/15549945?hl=en
- Manage OAuth Clients: https://support.google.com/cloud/answer/15549257?hl=en
- Verify Google ID token server-side: https://developers.google.com/identity/gsi/web/guides/verify-google-id-token
- Google OpenID Connect: https://developers.google.com/identity/openid-connect/openid-connect

## Prerequisiti

- Account Google Workspace aziendale.
- Permessi per creare o amministrare un progetto Google Cloud nella Organization aziendale.
- Domini Workspace autorizzati: `unguess.io` e `nuotounostiledivita.it`.
- Dominio del servizio Access Layer in produzione: `access-layer.unguess-internal.net`.
- URL previsti per Access Layer:
  - local: `http://localhost:8080/access-control/v1/auth/google/callback`
  - production: `https://access-layer.unguess-internal.net/v1/auth/google/callback`

Nota: `GOOGLE_ALLOWED_HD` deve contenere solo domini Google Workspace validati tramite claim `hd` dell'ID token. Non inserire `localhost` in `GOOGLE_ALLOWED_HD`.

## 1. Creare o selezionare il progetto Google Cloud

1. Accedere a Google Cloud Console con account aziendale admin.
2. Creare un nuovo progetto, ad esempio `internal-access-layer-prod`.
3. Verificare che il progetto sia dentro la Google Cloud Organization aziendale.
4. Per v1 non e richiesto un ambiente staging separato, salvo richiesta successiva.

Raccomandazione: se in futuro viene introdotto staging, usare un progetto separato e un OAuth client separato.

## 2. Configurare Google Auth Platform

1. Aprire Google Auth Platform nel progetto selezionato.
2. Se e la prima app, scegliere `Get started`.
3. Inserire app name, ad esempio `Access Layer Interno`.
4. Impostare user support email, preferibilmente una Google Group monitorata sul dominio aziendale, ad esempio `lorenzo.prandi@unguess.io`.
5. Inserire developer contact information.
6. Salvare.

## 3. Impostare Audience interna

1. Aprire la sezione Audience della Google Auth Platform.
2. Se disponibile, selezionare `Internal`.
3. Se `unguess.io` e `nuotounostiledivita.it` appartengono alla stessa Google Workspace Organization, verificare che l'audience interna limiti l'autorizzazione agli utenti di quella Organization.
4. Se i due domini appartengono a Workspace/Organization diverse, usare audience esterna con soli scope `openid email profile` e lasciare al backend Access Layer il controllo finale tramite `GOOGLE_ALLOWED_HD`.

Nota: anche usando audience interna, il backend Access Layer deve comunque validare il claim `hd` dell'ID token.

## 4. Configurare Data Access / Scopes

Access Layer richiede solo login e identita base.

Scopes da usare nella richiesta OIDC:

```text
openid email profile
```

Non richiedere scopes Gmail, Drive, Calendar o altri accessi Google se non servono esplicitamente.

## 5. Creare OAuth Client Web

1. Aprire la pagina Clients / OAuth clients nella Google Auth Platform.
2. Cliccare `Create client`.
3. Tipo applicazione: `Web application`.
4. Nome: `Access Layer Web Client - production`.
5. Inserire Authorized JavaScript origins se si usa Google Identity Services lato browser nella pagina Access Layer. Per il flusso server redirect puro puo non essere necessario, ma e utile se l'admin UI avvia login da frontend:
   - `https://access-layer.unguess-internal.net`
   - `http://localhost:8080` nel progetto dev
6. Inserire Authorized redirect URIs:
   - `http://localhost:8080/access-control/v1/auth/google/callback`
   - `https://access-layer.unguess-internal.net/v1/auth/google/callback`
7. Creare il client.
8. Copiare subito `Client ID` e `Client Secret`.
9. Salvare il client secret in un secret manager, non nel repository.

## 6. Configurare Access Layer

Aggiornare le variabili ambiente:

```env
GOOGLE_CLIENT_ID=<client-id>.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=<client-secret>
GOOGLE_REDIRECT_URI=https://access-layer.unguess-internal.net/v1/auth/google/callback
GOOGLE_ALLOWED_HD=unguess.io,nuotounostiledivita.it
GOOGLE_OIDC_SCOPE=openid email profile
```

Per lo sviluppo locale usare `GOOGLE_REDIRECT_URI=http://localhost:8080/access-control/v1/auth/google/callback`, mantenendo comunque `GOOGLE_ALLOWED_HD=unguess.io,nuotounostiledivita.it`.

## 7. Configurare Authorized domains e branding

1. Nella configurazione branding, inserire nome app e contatti.
2. Aggiungere domini autorizzati se richiesto dalla console.
3. Verificare la proprieta dei domini se Google la richiede.
4. Per app interna con soli scopes base, normalmente non serve una verifica pubblica, ma eventuali modifiche a scopes sensibili/restricted possono attivare verifica.

## 8. Controlli Google Workspace Admin opzionali

Se l'organizzazione blocca app OAuth non approvate:

1. Aprire Google Admin Console.
2. Sezione sicurezza / API controls / App access control.
3. Registrare l'OAuth Client ID di Access Layer come app interna attendibile, secondo policy aziendale.
4. Testare con un utente non admin.

## 9. Test obbligatori

### Utente aziendale autorizzato

- Login con `utente@unguess.io` e con `utente@nuotounostiledivita.it`.
- `hd` deve essere rispettivamente `unguess.io` o `nuotounostiledivita.it`.
- Grant attivo per il tool.
- Risultato: accesso consentito, audit `auth.allowed` e `token.exchanged`.

### Utente aziendale non autorizzato

- Login con `utente2@unguess.io` senza grant.
- Risultato: accesso negato, audit `auth.denied.no_grant`.

### Utente esterno

- Login con account non aziendale.
- Risultato: negato da Google se audience interna lo blocca, o negato dal backend per `hd` mancante/non valido.
- Audit: `auth.denied.external_domain` quando il callback arriva al backend.

### Redirect URI errato

- Provare con `return_url` non allow-listato.
- Risultato: negato prima del redirect Google, audit `auth.denied.invalid_return_url`.

## 10. Checklist finale

- [ ] Progetto Google Cloud dentro Organization aziendale.
- [ ] Audience impostata a Internal se disponibile.
- [ ] OAuth Client tipo Web application creato.
- [ ] Redirect URI esatto configurato.
- [ ] Client ID e Client Secret salvati come secret.
- [ ] `GOOGLE_ALLOWED_HD` configurato.
- [ ] Test interno/esterno completati.
- [ ] Nessun token Google salvato o loggato.
