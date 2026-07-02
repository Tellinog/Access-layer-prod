# Access Layer Google SSO - guida per persone

Questo repository e una base pronta per sviluppare un layer di accesso comune per tool interni.

Il valore del progetto non e solo il login Google. Il valore e avere un punto unico dove sapere:

- quale utente aziendale ha chiesto accesso;
- per quale tool lo ha chiesto;
- se il dominio Google e valido;
- se l'utente e autorizzato;
- quale sessione e stata rilasciata;
- quale decisione di accesso e stata presa;
- quali log sono disponibili per audit e sicurezza.

## Perche centralizzare

Senza un layer comune, ogni tool implementa login, controlli, autorizzazioni e log in modo diverso. Questo aumenta rischio di bug, account esterni, permessi incoerenti e log non affidabili.

Con Access Layer:

- Google resta identity provider;
- Access Layer diventa authorization gateway aziendale;
- ogni tool riceve una identita gia verificata;
- admin e auditor hanno un punto unico per permessi e accessi;
- i tool mantengono solo la sessione locale e i log applicativi.

## Come usare questo pacchetto

1. Compilare le variabili aziendali in `BACKLOG.md` e `.env.example`.
2. Creare il progetto Google seguendo `docs/GOOGLE_CLOUD_SETUP.md`.
3. Consegnare il repository a Codex con `prompts/CODEX_SHORT_PROMPT.md`.
4. Durante lo sviluppo, far rispettare `AGENTS.md`.
5. Prima del rilascio, verificare `docs/TESTING.md`, `docs/SECURITY.md` e `docs/DEPLOYMENT.md`.

## Risultato minimo accettabile

La prima versione e accettabile quando un tool pilota puo:

- inviare l'utente ad Access Layer;
- completare login Google con account aziendale;
- ricevere negazione per account esterni o non autorizzati;
- ricevere identita e permessi quando autorizzato;
- registrare nei propri log `google_sub`, `email`, `tool_slug`, `access_session_id` e `correlation_id`;
- mostrare agli admin i log di accesso del layer centrale.
