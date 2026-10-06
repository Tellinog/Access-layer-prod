# ADMIN_GUIDE.md

## OAuth page layout (2026-10-06)

`/admin/oauth` is organized in tabs: **Overview** (counts, setup order, current state, advanced snapshot), **User access** (native human grants), **Scopes**, **Resources**, **Clients** and **Lifecycle & keys** (registration status, credential rotation/retirement, signing keys). The URL hash keeps the current tab. The right-hand panel always shows the one-time credential result and the last operation result; errors also appear as a toast with the correlation ID.

In **User access**, choose the native resource once; it applies to the single grant, bulk grant and existing-grant list. **One user** searches by email or name and lists matches; **Several users or emails** combines searched users (Add or double-click) and pasted emails. A person appears in search only after their first Access Layer sign-in. To pre-authorize someone who has never signed in, paste the email in **Several users or emails** (or use **Pre-authorize … as pending** from a no-match search): with an approved domain (`GOOGLE_ALLOWED_HD` or `MICROSOFT_ALLOWED_EMAIL_DOMAINS`) the preview shows `create_pending`, and commit stores `pending_user_link` grants. They activate automatically at the person's first verified sign-in (Google or Microsoft) and authorize nothing before. Other domains show `email_domain_not_allowed`; suspended/disabled users stay errors. Pending grants appear in **Existing grants** (status filter `pending_user_link`) and can be revoked.

## Phase 9A.4 OAuth bulk workflows

Use `/admin/oauth` with an active platform-admin session and explicit `admin:oauth:read/write`. Normal administration selects clients and resources by readable name, canonical URI/ID, mode and status. Internal UUIDs remain in the advanced snapshot for troubleshooting.

For **Bulk scope catalogue**, paste one `scope ; description` or `scope<TAB>description` row per line. Blank lines are ignored, CRLF/LF and a UTF-8 BOM are tolerated, whitespace is trimmed, and only the first TAB (otherwise first semicolon) separates columns. Later semicolons and commas remain in the description. Missing columns retain the original line number as an error. Preview shows every row and its operation. Commit is enabled only for the current successful preview. Editing input or options invalidates it. Existing descriptions and disabled scopes are unchanged unless their explicit options are selected. Batches are limited to 200 rows.

The scope catalogue supports scope/status filtering, checkbox selection and status preview with affected resource/client counts. Disabling does not delete registrations, allowances or grants. The resource picker supports search, select/clear visible, select all active, clear all and a selected count. Native resource scope administration applies explicit register/activate or disable operations; unchecked scopes remain untouched and native legacy permission mappings remain null. Legacy-bridge mappings retain the existing exact registered-key rules.

Structured client allowances select a resource and its exact current active registered scopes. Select all captures that finite set; it grants no wildcard or future scope. New-client creation can select the entire resource scope set once. Existing-client editing preserves other resource allowances and previews add/remove/unchanged before replacement. Advanced `resource URI = scope` paste remains available and previews its complete replacement. Redirect URIs remain one per line, with readable client selection, current values and a preview diff. Replacement commits reject a changed current set and require another preview.

Bulk native grants select one native resource, exact scopes, existing users and optional validity. Search/select users or paste existing email addresses one per line. Emails resolve server-side only to existing active users; unknown/inactive targets fail preview and no pending grant is written. At most 100 user inputs, 50 scopes and 1,000 pairs are accepted. Effective exact grants skip; elapsed active rows expire before re-grant in the same transaction. The dedicated grant list has resource, user/email, scope, persisted-status and effective filters with 100-row pages. Checkbox selection previews and revokes at most 200 exact grant IDs; terminal rows skip.

Bulk operations are scope catalogue/lifecycle, native scope registration, allowance UX, native grants and exact revocation. Resource/client creation, credential rotation and signing-key transitions remain single-entity by design. Credentials appear once in their dedicated panel and are discarded before another mutation. Never use the simulation fixture as production registration.

## Ruoli admin

| Ruolo | Scopo |
|---|---|
| `platform_admin` | Gestisce tutti i tool, utenti, grant, backup, secret rotation e log |
| `tool_admin` | Gestisce grant di uno o piu tool assegnati |
| `auditor` | Legge audit log senza modificare configurazione |
| `user` | Accede solo ai tool autorizzati |

OAuth P0 administration is intentionally narrower: only `platform_admin` with `admin:oauth:read` or `admin:oauth:write` may use it. `tool_admin` assignments do not grant OAuth administration.

## OAuth administration (Phase 9A.3)

Open `/admin/oauth` in production (or `/access-control/oauth` under the local base path). The page is part of the same Access Layer service and uses the existing Admin session, CSRF and audit model.

The Admin navigation shows the OAuth link after `/v1/me` confirms `role=platform_admin` and `admin:oauth:read`. The server checks the active session grant again on every OAuth Admin request; the link alone does not authorize access.

If `/admin/oauth` returns `ADMIN_FORBIDDEN`, check the current `/v1/me` response and the active `access-admin` grant. The grant must have role `platform_admin` and explicit `admin:oauth:read`; mutations also require `admin:oauth:write`. After deploying D-048, edit the **existing active** grant for `access-admin`: preserve its permissions, select `admin:oauth:read` and `admin:oauth:write`, save, then reload `/v1/me` and `/admin/oauth`. Creating a second grant for the same person/tool is unnecessary and may conflict with the existing grant. D-048 accepts the two official access-request keys containing `_` so all 15 platform-admin permissions can be saved together. If the API returns `VALIDATION_ERROR` with `details.unknown_permissions`, inspect the registered keys in **Tools > access-admin**. A remaining `400` needs its response body and correlation ID investigated; request-completion logs do not include response bodies.

Native onboarding order:

1. Create canonical `project:domain:action` scopes.
2. Create a resource with mode **Native** (the UI default) and select its exact active scopes. Copy its one-time introspection credential.
3. Search for an existing Access Layer user by email or display name; the user must have logged in at least once and be active. Select the resource's registered scopes and optional validity dates, then grant. The grant belongs to internal `users.id`.
4. Create a confidential client with an exact redirect URI and explicit resource/scope allowances. Copy its one-time secret.
5. Prepare, publish and activate an OAuth signing key using the existing lifecycle. Keep the protocol flag under its separate rollout control.
6. Review the resource-filtered **Native human grants** list. Revoking one scope immediately changes online introspection, refresh and later authorization decisions. A local JWT can remain cryptographically valid until expiry. To restore access, create a new grant row.

An elapsed `active` grant is changed to terminal `expired` before re-granting the same user/resource/scope. A still-current active grant returns a conflict and is never silently replaced. Native pending-email grants, automatic email linking and resource mode migration are not available.

Legacy-bridge compatibility onboarding order:

1. create each canonical `project:domain:action` scope;
2. create the HTTPS resource with mode **Legacy bridge**, select one existing entitlement-only legacy tool from the live dropdown and map every scope to one exact registered permission of that tool;
3. copy the generated resource introspection credential once;
4. create the confidential BFF client with exact redirects and explicit resource/scope allowances;
5. copy the generated client secret once;
6. use the existing Users/Grants UI to create the human grant on the bound legacy tool;
7. generate a staged OAuth signing key, publish it, wait until the displayed activation time, then activate it;
8. keep `OAUTH_P0_ENABLED=false` until separate pilot and production gates approve enablement.

Secrets shown in a one-time result panel cannot be retrieved again. Rotation immediately retires the previous active credential and returns a new plaintext value once. Client secrets, resource secrets, hashes and private signing keys never appear in list/read responses or audit metadata.

The legacy tool is only the compatibility entitlement anchor for old consumers. It must not be used as `client_id`, resource/audience or introspection credential. New native resources have no legacy tool, binding or permission mapping.

## Bootstrap primo admin

Aprendo la root Admin UI senza sessione valida, il servizio avvia direttamente il login Google per il tool riservato `access-admin`; la dashboard viene servita solo dopo una sessione admin valida.

La sessione Admin usa un JWT di 15 minuti e un refresh token protetto in un cookie HttpOnly separato. Le azioni dell'admin rinnovano la sessione e spostano in avanti il timeout inattivo di 8 ore; una pagina lasciata aperta senza attività non viene mantenuta viva da timer in background.

Al primo deploy, impostare `ADMIN_BOOTSTRAP_EMAILS` con una o piu email aziendali.

Dopo il primo login degli admin:

1. creare grant `platform_admin` persistente per l'admin UI;
2. rimuovere o svuotare `ADMIN_BOOTSTRAP_EMAILS` in produzione;
3. registrare l'evento in `DEVLOG.md` se cambia configurazione.

## Creare un tool

1. Aprire Admin UI.
2. Sezione Tools.
3. Inserire `slug`, `display_name`, descrizione e owner.
4. Inserire uno o piu `allowed_return_urls`.
5. Creare tool client.
6. Copiare client ID e secret una sola volta e consegnarlo tramite canale sicuro al maintainer del tool.
7. Creare permission keys consigliate come segmenti gerarchici separati da due punti, per esempio `tool:read`, `forecasting:write` o `petyr:read:all`. Sono ammessi solo minuscole, numeri e trattini in ogni segmento.

V1 richiede che i permessi non vuoti assegnati nei grant esistano tra le permission keys del tool. I grant possono comunque essere role-only usando `permissions=[]`.

## Modificare o eliminare un tool

Dal dettaglio tool:

1. usare `Modifica` per abilitare i campi modificabili;
2. aggiornare nome, descrizione, stato, owner, Return URL e permission keys nel formato gerarchico `namespace:azione[:ambito...]`, per esempio `petyr:read:all`;
3. premere `Salva modifiche` e verificare il feedback `Modifica salvata.` oppure il messaggio di errore con eventuale codice di correlazione;
4. usare `Elimina` solo per tool non riservati e dopo conferma distruttiva.

L'eliminazione rimuove il tool e i dati operativi collegati tramite cascade database, inclusi client, permission keys, grant, sessioni e richieste. Gli audit storici restano consultabili: il `tool_id` viene azzerato dal vincolo FK, mentre `tool_slug` rimane disponibile.

Il tool riservato `access-admin` non puo essere eliminato.

## Autorizzare un utente

Opzione A - utente gia noto:

1. Cercare utente per email o Google sub.
2. Aprire il dettaglio dell'utente: la tabella `Tool e autorizzazioni` mostra un grant per riga, con ruolo, permessi, stato e scadenza.
3. Usare `Aggiungi tool`, scegliere il tool dal menu a tendina e aprire l'elenco dei permessi: le checkbox mostrano solo le permission key registrate per quel tool.
4. Salvare.

Opzione B - utente non ancora entrato:

1. Creare grant tramite email aziendale.
2. Stato: `pending_user_link`.
3. Al primo login con un provider approvato, Access Layer collega il grant se identita, email e dominio sono validi.
4. Dopo il link, il grant diventa attivo per lo user ID.

Le email per grant pendenti devono essere ben formate e usare un dominio presente in `GOOGLE_ALLOWED_HD` oppure in `MICROSOFT_ALLOWED_EMAIL_DOMAINS`. La configurazione Testbirds prevista include `testbirds.com` e `testbirds.de`; questo consente di preparare grant pendenti ma non abilita da solo il login Microsoft.

## Viste per tool e utente

- Nel dettaglio di un tool, un `platform_admin` vede una riga per ogni utente gia registrato su Access Layer, con accesso effettivo, ruoli, permission key e stato dei grant. Da qui puo concedere un grant a chi non e autorizzato o gestire quelli esistenti. L'implementazione v1 usa l'attuale limite di 200 righe delle API Admin; pianificare paginazione server-side prima di superarlo.
- Nel dettaglio di un utente, la tabella `Tool e autorizzazioni` raccoglie tutti i grant dell'utente. L'elenco Utenti resta quindi una riga per persona, non una riga per combinazione utente/tool.
- Un `tool_admin` resta limitato ai tool assegnati: nel dettaglio tool vede i grant visibili per il proprio perimetro, ma non l'elenco completo degli utenti non autorizzati.
- I menu dei tool mostrano il catalogo attualmente visibile all'admin; l'elenco espandibile dei permessi usa checkbox e mostra solo le permission key registrate per il tool scelto. Un grant role-only con `permissions=[]` resta valido.

## Bulk import/export grant

Usare `Grant > Rilascia grant in blocco` per assegnare lo stesso grant a molte email: inserire una email aziendale per riga, scegliere tool, ruolo, permission key e scadenza opzionale dall'interfaccia, poi eseguire Preview e confermare.

Usare `Grant > Importa CSV avanzato` quando la stessa importazione deve contenere tool, ruoli, azioni o permission key differenti tra righe.

Flusso consigliato:

1. Scaricare `Template CSV`.
2. Scaricare `Export permessi` per verificare `tool_slug` e permission key disponibili.
3. Compilare il CSV con colonne `email,tool_slug,role,permissions,valid_until,action,note`. Sono accettati sia la virgola (`,`) sia il punto e virgola (`;`) come separatore.
4. Incollare il CSV in `Importa CSV avanzato` e lanciare `Preview`.
5. Correggere tutte le righe `error`.
6. Lanciare `Commit import` solo quando la preview non contiene errori.

Regole:

- `upsert` crea un nuovo grant solo se la stessa email normalizzata non ha gia un grant `active` o `pending_user_link` per quel tool; il primo grant esistente resta invariato anche se ruolo, permessi o scadenza della nuova riga differiscono;
- se la stessa email/tool compare piu volte nello stesso file, solo la prima riga valida puo creare il grant e le successive sono ignorate con warning;
- `revoke` revoca grant non revocati per email/tool e ruolo opzionale;
- utenti gia noti diventano grant `active`;
- email aziendali non ancora note diventano `pending_user_link` e non richiedono approvazione ulteriore al primo login;
- account esterni o permission key non registrate vengono bloccati in preview/commit.

## Revocare accesso

1. Cercare grant.
2. Impostare `revoked`.
3. Scegliere se revocare sessioni attive del tool.
4. Verificare audit event `admin.grant.revoked` e, se sessioni revocate, `session.revoked`.

## Disabilitare un utente

Usare quando un utente non deve accedere ad alcun tool anche se possiede grant.

1. Cercare utente.
2. Impostare `status=disabled` o `suspended`.
3. Revocare sessioni attive.
4. Audit obbligatorio.

## Consultare log

Filtri minimi:

- data/ora;
- `tool_slug`;
- email;
- Google sub;
- outcome;
- reason code;
- correlation ID;
- IP hash.

I log devono essere read-only per auditor e non modificabili da tool admin.

## Gestire richieste di accesso

Quando un utente aziendale valido prova ad accedere a un tool senza grant, la Admin UI mostra una richiesta pendente nella sezione `Richieste accesso`.

1. Aprire Admin UI.
2. Entrare in `Richieste accesso`.
3. Filtrare per tool, email o stato `pending`.
4. Verificare email, dominio, tool richiesto, numero tentativi e ultimo `correlation_id`.
5. Scegliere una delle azioni:
   - `Approva`: selezionare ruolo e permessi; il sistema crea il grant.
   - `Rifiuta`: inserire una nota opzionale; nessun grant viene creato.
   - `Chiudi`: usare per test, duplicati o richieste non operative.
6. Comunicare all'utente di riprovare l'accesso, se approvato.

Gli account esterni o con dominio Google non valido non devono apparire in questa sezione: restano consultabili solo nei log di sicurezza.

## Backup e restore

I backup scaricati dalla Admin UI sono JSON cifrati con `BACKUP_ENCRYPTION_KEY`.

- `admin:backup:read` consente il download del backup cifrato.
- `admin:backup:write` consente l'import/restore.
- `admin:backup:secrets` consente solo a platform admin espliciti di scaricare il materiale di restore.

Il materiale di restore contiene `TOOL_CLIENT_SECRET_PEPPER` e `BACKUP_ENCRYPTION_KEY`. Non contiene i vecchi per-tool client secret `tls_...`, perche' Access Layer li mostra una sola volta e poi conserva solo hash.
