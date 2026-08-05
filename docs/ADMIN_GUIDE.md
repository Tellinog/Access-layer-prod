# ADMIN_GUIDE.md

## Ruoli admin

| Ruolo | Scopo |
|---|---|
| `platform_admin` | Gestisce tutti i tool, utenti, grant, backup, secret rotation e log |
| `tool_admin` | Gestisce grant di uno o piu tool assegnati |
| `auditor` | Legge audit log senza modificare configurazione |
| `user` | Accede solo ai tool autorizzati |

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
3. Al primo login, Access Layer collega il grant se email e `hd` sono validi.
4. Dopo il link, il grant diventa attivo per lo user ID.

Le email per grant pendenti devono essere ben formate e usare un dominio presente in `GOOGLE_ALLOWED_HD`.

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

- `upsert` crea un nuovo grant o aggiorna un grant attivo/pendente esistente per stessa email, tool e ruolo;
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
