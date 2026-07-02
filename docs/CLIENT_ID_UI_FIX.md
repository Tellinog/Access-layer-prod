# Client ID nella UI Admin

Questo pacchetto corregge la gestione del Tool Client ID nella UI Admin.

## Problema riscontrato

Il backend di Access Layer generava correttamente `tool_client_id` e `tool_client_secret` nelle risposte di creazione tool e rotazione secret, ma la UI mostrava solo il secret.

## Modifiche applicate

- La schermata finale dopo `Nuovo tool` ora mostra:
  - `ACCESS_LAYER_CLIENT_ID`;
  - `ACCESS_LAYER_CLIENT_SECRET`;
  - blocco env copiabile con entrambe le variabili.
- La schermata finale dopo `Ruota secret` ora mostra anche il nuovo Client ID.
- La lista Tools e il dettaglio tool mostrano i Client ID attivi già presenti a database.
- Il client secret resta mostrato solo una volta, come previsto.

## Cosa usare in Presidio/Arya

```env
ACCESS_LAYER_CLIENT_ID=tlc_...
ACCESS_LAYER_CLIENT_SECRET=tls_...
```

## Se hai già creato il tool prima della correzione

Dopo aver avviato questo pacchetto aggiornato, apri la sezione Tools: la colonna `Client ID` e il dettaglio tool mostrano il Client ID esistente. Se devi generare anche un nuovo secret, usa `Ruota secret` e copia il nuovo blocco env.
