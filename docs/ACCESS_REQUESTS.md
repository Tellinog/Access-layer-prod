# ACCESS_REQUESTS.md

## Obiettivo

Quando un utente aziendale valido tenta di accedere a un tool per cui non ha ancora un grant attivo, Access Layer deve trasformare il diniego in una richiesta di accesso visibile nella Admin UI.

Questo non sostituisce gli audit log: gli audit log restano la traccia immutabile del tentativo, mentre le access request sono una coda operativa per l'admin.

## Regola principale

Creare o aggiornare una access request solo quando tutte le condizioni sono vere:

1. login Google completato correttamente;
2. ID token Google valido;
3. `email_verified=true`;
4. `hd` presente e incluso nei domini aziendali ammessi;
5. tool richiesto esistente e attivo;
6. `return_url` valida per il tool;
7. nessun grant attivo per utente/email/tool.

Non creare access request per account esterni, token Google invalidi, return URL non allow-listate, tool inesistenti o traffico chiaramente malevolo. Questi casi devono rimanere solo nei log di sicurezza.

## Comportamento al tentativo non autorizzato

Al verificarsi di `auth.denied.no_grant`:

1. Access Layer scrive l'audit event `auth.denied.no_grant`.
2. Access Layer esegue un upsert su `access_requests` usando la chiave logica `tool_id + email_normalized` per le richieste pendenti.
3. Se non esiste una richiesta pendente, crea una riga con `status=pending` e `attempts_count=1`.
4. Se esiste gia una richiesta pendente, aggiorna `last_seen_at`, `attempts_count`, `last_correlation_id`, IP hash e user agent hash.
5. Access Layer scrive `access_request.created` oppure `access_request.repeated`.
6. L'utente vede il messaggio di accesso non autorizzato con `correlation_id` e indicazione che la richiesta e stata registrata.
7. La Admin UI mostra un badge nella sezione `Richieste accesso`.

## Admin UI

La sezione `Richieste accesso` deve mostrare almeno:

- stato richiesta;
- tool richiesto;
- email utente;
- nome utente, se disponibile dal profilo Google;
- dominio `hd`;
- primo tentativo;
- ultimo tentativo;
- numero tentativi;
- ultimo `correlation_id`;
- esito dell'ultima decisione;
- azioni disponibili.

Filtri minimi:

- stato: pending, approved, rejected, closed;
- tool;
- email;
- intervallo date;
- richieste con piu tentativi.

Ordinamento default: `status=pending` prima, poi `last_seen_at DESC`.

## Azioni admin

### Approva

L'approvazione deve:

1. creare un grant attivo per il tool e l'utente;
2. assegnare ruolo e permessi scelti dall'admin;
3. collegare la richiesta al `grant_id` creato;
4. impostare la richiesta a `approved`;
5. scrivere audit event `admin.access_request.approved` e `admin.grant.created`;
6. rendere valido il successivo login dell'utente.

L'approvazione non deve creare sessioni automatiche: l'utente dovra rieseguire login o riprovare l'accesso al tool.

### Rifiuta

Il rifiuto deve:

1. impostare la richiesta a `rejected`;
2. salvare una nota opzionale;
3. scrivere audit event `admin.access_request.rejected`;
4. lasciare invariati eventuali grant esistenti per altri tool.

Dopo un rifiuto, nuovi tentativi dello stesso utente/tool possono essere registrati come nuovo evento o riaprire la richiesta secondo configurazione. Default v1: riaprire solo se `ACCESS_REQUEST_REOPEN_AFTER_DAYS` e trascorso. Prima della scadenza della finestra, Access Layer mantiene solo l'audit `auth.denied.no_grant` e scrive `access_request.reopen_suppressed` senza creare una nuova riga pendente.

### Chiudi senza decisione

Usare per duplicati, test o casi non operativi.

## Notifiche

V1 obbligatoria:

- badge/counter nella Admin UI;
- lista richieste pendenti;
- audit event per creazione, ripetizione, approvazione e rifiuto.

V1 opzionale/configurabile:

- email agli admin del tool;
- webhook Slack/Teams;
- riepilogo giornaliero.

Le notifiche esterne non devono includere dati sensibili. Includere solo tool, email, timestamp e link alla Admin UI.

## Privacy e sicurezza

- Non inviare notifiche operative per account esterni: evitare enumeration e rumore.
- Non mostrare raw IP di default; usare hash come negli audit log.
- Non includere token, authorization code o client secret nella richiesta.
- Limitare la visibilita ai `platform_admin` e ai `tool_admin` assegnati al tool.
- Rate limitare i tentativi ripetuti per evitare spam verso l'admin.
