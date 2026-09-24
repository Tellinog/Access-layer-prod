# COPY.md

## Login button

- `Accedi con Google aziendale`

## Temporary provider chooser

- Title: `Choose how to continue`
- Heading: `Sign in to {escaped_tool_display_name}`
- Supporting copy: `Choose your company account provider.`
- Actions: `Continue with Google`; `Continue with Microsoft`

This English copy is the explicit D-045 legacy exception for allowlisted tools. Do not show it when the bridge is disabled or the tool is not allowlisted.

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
- `Aggiungi tool`
- `Concedi grant`
- `Gestisci grant`
- `Rilascia grant in blocco`
- `Anteprima`
- `Conferma rilascio`
- `Seleziona i permessi`
- `{count} permessi selezionati`
- `Se email e tool hanno già un grant attivo o pendente, il primo grant resta invariato.`
- `Client ID e client secret generati per il tool. Client secret mostrato una sola volta: copia entrambi ora e conservali in modo sicuro.`
- `Compila slug, nome e almeno una Return URL.`

## OAuth P0 administration

- `Temporary P0 compatibility state.`
- `Native OAuth entitlement domains must replace this bridge after the Nancy Phase 8 pilot and before broad SDK-native rollout.`
- `Protocol enablement remains controlled separately by OAUTH_P0_ENABLED.`
- `Rotate and show secret once`
- `Copy now; it cannot be shown again.`
- `Private keys are generated server-side into the configured protected root and are never returned.`
