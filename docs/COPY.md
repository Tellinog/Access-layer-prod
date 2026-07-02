# COPY.md

## Login button

- `Accedi con Google aziendale`

## Logout button

- `Logout`

## Admin unauthenticated state

The Admin UI root does not show unauthenticated dashboard copy. It redirects into the Google login flow for the reserved `access-admin` tool.

## Generic denial

- `Accesso non disponibile per questo tool.`
- `Se pensi sia un errore, contatta un amministratore e comunica questo codice: {correlation_id}.`

## External account denial

- `Questo servizio e riservato agli account aziendali.`

## No grant denial

- `Il tuo account aziendale e valido, ma non risulta autorizzato per questo tool. La richiesta e stata registrata per un amministratore. Codice: {correlation_id}.`

## Invalid session

- `Sessione scaduta. Accedi di nuovo.`

## Admin save success

- `Modifica salvata.`
- `Tool eliminato.`
- `Salvataggio non riuscito: {message}`
- `Eliminazione non riuscita: {message}`

## Admin destructive confirmation

- `Confermi la revoca dell'accesso? Le sessioni attive potrebbero essere terminate.`

## Copy rules

- Do not reveal detailed security internals to end users.
- Always show `correlation_id` on failures.
- Avoid blaming the user.
- For admin pages, use explicit labels: tool, utente, ruolo, permessi, stato, scadenza.

## Admin inline forms

- `Salva tool`
- `Salva grant`
- `Approva e salva grant`
- `Rifiuta richiesta`
- `Chiudi richiesta`
- `Modifica`
- `Salva modifiche`
- `Elimina`
- `Ruota secret`
- `Client ID e client secret generati per il tool. Client secret mostrato una sola volta: copia entrambi ora e conservali in modo sicuro.`
- `Compila slug, nome e almeno una Return URL.`
