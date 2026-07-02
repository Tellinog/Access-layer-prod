# Access Layer Integration URL Specification

## Scopo

Questa specifica definisce come ogni servizio integrato con Access Layer deve configurare gli URL usati nel flusso di autenticazione/autorizzazione.

Il punto fondamentale è che un'integrazione non deve usare un solo URL generico di Access Layer per tutto. Deve distinguere tra:

1. URL pubblico usato dal browser dell'utente;
2. URL interno usato dal backend del servizio integrato;
3. callback URL pubblico del servizio integrato.

Questa separazione evita errori in locale con Docker e rende la configurazione corretta anche in ambienti come Coolify, Hetzner, reverse proxy e reti private tra container.

---

## Variabili obbligatorie per i servizi integrati

Ogni tool o servizio che usa Access Layer dovrebbe supportare almeno queste variabili:

```env
ACCESS_LAYER_PUBLIC_BASE_URL=
ACCESS_LAYER_INTERNAL_BASE_URL=
ACCESS_LAYER_CALLBACK_URL=
ACCESS_LAYER_TOOL_SLUG=
ACCESS_LAYER_CLIENT_ID=
ACCESS_LAYER_CLIENT_SECRET=
```

Per retrocompatibilita', si puo' mantenere anche:

```env
ACCESS_LAYER_BASE_URL=
```

ma non deve essere l'unica sorgente di configurazione. Se presente, puo' essere usata come fallback per `ACCESS_LAYER_PUBLIC_BASE_URL` e `ACCESS_LAYER_INTERNAL_BASE_URL` solo quando le due variabili specifiche non sono impostate.

---

## Significato delle variabili

### ACCESS_LAYER_PUBLIC_BASE_URL

URL pubblico di Access Layer, cioe' quello raggiungibile dal browser dell'utente.

Viene usato per:

- redirect del browser verso Access Layer;
- costruzione della login URL;
- link visibili o navigabili dall'utente.

Esempio locale:

```env
ACCESS_LAYER_PUBLIC_BASE_URL=http://localhost:8080/access-control
```

Esempio Coolify/produzione:

```env
ACCESS_LAYER_PUBLIC_BASE_URL=https://access-layer.example.com
```

### ACCESS_LAYER_INTERNAL_BASE_URL

URL usato dal backend del servizio integrato per chiamare Access Layer server-to-server.

Viene usato per:

- exchange del one-time code;
- introspection della sessione/token;
- logout server-side;
- eventuali chiamate API interne ad Access Layer.

Esempio locale con Docker Desktop:

```env
ACCESS_LAYER_INTERNAL_BASE_URL=http://host.docker.internal:8080/access-control
```

Esempio produzione semplice, passando dal dominio pubblico:

```env
ACCESS_LAYER_INTERNAL_BASE_URL=https://access-layer.example.com
```

Esempio produzione con rete privata tra container, se supportata e configurata:

```env
ACCESS_LAYER_INTERNAL_BASE_URL=http://access-layer:8080
```

Nota: l'URL interno non deve necessariamente essere apribile dal browser dell'utente. Deve essere raggiungibile dal container/backend del servizio integrato.

### ACCESS_LAYER_CALLBACK_URL

URL pubblico del servizio integrato dove Access Layer deve rimandare il browser dopo aver autorizzato l'utente.

Viene salvato/validato come allowed return URL nel tool registrato dentro Access Layer.

Esempio locale:

```env
ACCESS_LAYER_CALLBACK_URL=http://localhost:8081/auth/callback
```

Esempio Coolify/produzione:

```env
ACCESS_LAYER_CALLBACK_URL=https://arya.example.com/auth/callback
```

Questo URL deve essere raggiungibile dal browser dell'utente, non solo dai container.

---

## Regola di utilizzo nel codice

Un servizio integrato deve usare gli URL cosi':

```text
/auth/login
  usa ACCESS_LAYER_PUBLIC_BASE_URL
  perche' deve fare redirect del browser verso Access Layer

/auth/callback
  riceve il browser su ACCESS_LAYER_CALLBACK_URL
  poi usa ACCESS_LAYER_INTERNAL_BASE_URL
  per fare exchange server-to-server del one-time code

introspect/session check
  usa ACCESS_LAYER_INTERNAL_BASE_URL
  perche' e' una chiamata backend-to-backend

logout
  usa ACCESS_LAYER_INTERNAL_BASE_URL per invalidare sessioni/token lato server
  usa eventualmente ACCESS_LAYER_PUBLIC_BASE_URL solo se deve fare redirect browser verso una pagina Access Layer
```

---

## Perche' non basta ACCESS_LAYER_BASE_URL

In locale, browser e container vedono la rete in modo diverso.

Per il browser:

```text
http://localhost:8080/access-control
```

significa Access Layer esposto sulla macchina host.

Per un container Docker:

```text
http://localhost:8080/access-control
```

significa il container stesso, non Access Layer.

Quindi, se un servizio usa `localhost` per le chiamate server-to-server, fallira' l'exchange del codice o l'introspection.

Al contrario, se il servizio usa:

```text
http://host.docker.internal:8080/access-control
```

per costruire il redirect browser, il browser potrebbe non risolvere correttamente quell'host o comunque si otterrebbe una URL non adatta all'utente finale.

La soluzione corretta e' separare URL pubblico e URL interno.

---

## Configurazione locale consigliata

Access Layer esposto su porta host 8080, servizio integrato Arya/Presidio esposto su porta host 8081.

Nel servizio integrato:

```env
ACCESS_LAYER_PUBLIC_BASE_URL=http://localhost:8080/access-control
ACCESS_LAYER_INTERNAL_BASE_URL=http://host.docker.internal:8080/access-control
ACCESS_LAYER_CALLBACK_URL=http://localhost:8081/auth/callback
ACCESS_LAYER_TOOL_SLUG=arya
ACCESS_LAYER_CLIENT_ID=tlc_xxx
ACCESS_LAYER_CLIENT_SECRET=tls_xxx
```

Nel tool registrato dentro Access Layer:

```text
slug: arya
allowed return url: http://localhost:8081/auth/callback
required permission: arya:access
admin permission, se prevista: arya:admin
```

Nella Google Cloud Console per Access Layer:

```text
Authorized redirect URI:
http://localhost:8080/access-control/v1/auth/google/callback
```

---

## Configurazione Coolify / Hetzner

In Coolify, normalmente l'utente non accede ai servizi tramite porte come `8080` o `8081`. Le porte restano interne ai container o al reverse proxy, mentre l'accesso pubblico avviene tramite dominio HTTPS.

Esempio:

```env
ACCESS_LAYER_PUBLIC_BASE_URL=https://access-layer.example.com
ACCESS_LAYER_INTERNAL_BASE_URL=https://access-layer.example.com
ACCESS_LAYER_CALLBACK_URL=https://arya.example.com/auth/callback
```

In questo caso, anche l'URL interno puo' coincidere con quello pubblico, perche' il backend del servizio integrato chiama Access Layer passando dal dominio pubblico e dal reverse proxy.

Se invece Coolify mette Access Layer e il servizio integrato sulla stessa rete Docker privata e si vuole evitare il passaggio dal dominio pubblico, si puo' usare un internal URL diverso:

```env
ACCESS_LAYER_PUBLIC_BASE_URL=https://access-layer.example.com
ACCESS_LAYER_INTERNAL_BASE_URL=http://access-layer:8080
ACCESS_LAYER_CALLBACK_URL=https://arya.example.com/auth/callback
```

Questa variante funziona solo se:

- il nome `access-layer` e' risolvibile dal container del servizio integrato;
- la porta interna indicata e' quella esposta dall'app dentro il container;
- l'eventuale base path configurato e' realmente servito anche sul traffico interno;
- cookie, issuer e redirect pubblici restano configurati con il dominio HTTPS pubblico.

In produzione, la configurazione piu' semplice e meno fragile e' spesso usare il dominio pubblico HTTPS anche per `ACCESS_LAYER_INTERNAL_BASE_URL`, almeno finche' non serve ottimizzare il traffico interno.

---

## Gestione delle porte: locale vs Coolify

### In locale

Le porte sono necessarie per distinguere i servizi sulla macchina di sviluppo:

```text
Access Layer: http://localhost:8080/access-control
Arya/Presidio: http://localhost:8081
```

Qui le porte fanno parte degli URL pubblici locali perche' il browser deve sapere quale servizio raggiungere.

### Su Hetzner con Coolify

Di norma non si usano URL pubblici con `:8080` o `:8081`.

Coolify espone i servizi tramite reverse proxy e dominio:

```text
https://access-layer.example.com
https://arya.example.com
```

Le porte continuano a esistere, ma restano un dettaglio interno del container/reverse proxy. L'utente e Google vedono solo gli URL HTTPS pubblici.

Quindi su Coolify bisogna configurare soprattutto:

- dominio pubblico del servizio Access Layer;
- dominio pubblico del tool integrato;
- eventuale rete interna tra servizi;
- allowed callback/return URL coerenti con i domini pubblici.

---

## Requisiti per Access Layer

Access Layer dovrebbe documentare esplicitamente questa distinzione nelle guide di integrazione dei tool.

In particolare, quando genera o mostra le credenziali di un tool, dovrebbe suggerire un template simile:

```env
ACCESS_LAYER_PUBLIC_BASE_URL=https://access-layer.example.com
ACCESS_LAYER_INTERNAL_BASE_URL=https://access-layer.example.com
ACCESS_LAYER_CALLBACK_URL=https://tool.example.com/auth/callback
ACCESS_LAYER_TOOL_SLUG=<tool-slug>
ACCESS_LAYER_CLIENT_ID=<tool-client-id>
ACCESS_LAYER_CLIENT_SECRET=<tool-client-secret>
```

Per sviluppo locale:

```env
ACCESS_LAYER_PUBLIC_BASE_URL=http://localhost:8080/access-control
ACCESS_LAYER_INTERNAL_BASE_URL=http://host.docker.internal:8080/access-control
ACCESS_LAYER_CALLBACK_URL=http://localhost:8081/auth/callback
```

---

## Checklist di integrazione per nuovi tool

Quando si integra un nuovo servizio con Access Layer, verificare sempre:

1. Il redirect browser usa `ACCESS_LAYER_PUBLIC_BASE_URL`.
2. Le chiamate backend-to-backend usano `ACCESS_LAYER_INTERNAL_BASE_URL`.
3. Il callback URL del servizio e' pubblico e coincide con l'allowed return URL registrato in Access Layer.
4. In locale, il container non usa `localhost` per chiamare Access Layer, salvo che Access Layer giri nello stesso container.
5. In Coolify/produzione, gli URL pubblici usano HTTPS e domini reali.
6. I Google OAuth redirect URI puntano alla callback Google pubblica di Access Layer, non alla callback del tool.
7. Il tool registrato in Access Layer contiene il callback URL pubblico del servizio integrato.
8. Le credenziali `ACCESS_LAYER_CLIENT_ID` e `ACCESS_LAYER_CLIENT_SECRET` appartengono allo stesso tool slug.
9. Il client secret non viene committato nel repository.
10. I file `.env` reali non vengono inclusi nello zip o nell'immagine Docker.

---

## Errori tipici

### Redirect verso host.docker.internal

Sintomo: aprendo il servizio, il browser viene mandato a `host.docker.internal`.

Causa: il codice sta usando l'URL interno per costruire il redirect browser.

Fix: usare `ACCESS_LAYER_PUBLIC_BASE_URL` per `/auth/login`.

### One-time code non consumato

Sintomo: Access Layer mostra `auth.allowed`, ma in `one_time_codes` il campo `consumed_at` resta vuoto.

Causa probabile: il servizio integrato non riesce a chiamare `/v1/auth/exchange`.

Fix: verificare `ACCESS_LAYER_INTERNAL_BASE_URL`, client ID e client secret.

### In Docker funziona il redirect ma fallisce callback/exchange

Causa frequente: `ACCESS_LAYER_INTERNAL_BASE_URL=http://localhost:8080/access-control` dentro il container.

Fix locale:

```env
ACCESS_LAYER_INTERNAL_BASE_URL=http://host.docker.internal:8080/access-control
```

### In produzione callback rifiutata

Causa frequente: `ACCESS_LAYER_CALLBACK_URL` non coincide esattamente con l'allowed return URL registrato in Access Layer.

Fix: allineare schema, dominio, path e slash finali.

---

## Principio finale

Ogni integrazione Access Layer deve trattare separatamente:

```text
URL pubblico di Access Layer    = dove mando il browser
URL interno di Access Layer     = dove il backend chiama Access Layer
Callback URL del tool           = dove Access Layer rimanda il browser
```

Questa separazione e' obbligatoria per evitare bug in locale, Docker, Coolify e produzione.
