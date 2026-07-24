# ERROR_MESSAGES.md

## User-safe messages

| Code | Message |
|---|---|
| `AUTH_INVALID_TOOL` | Tool non riconosciuto. Contatta un amministratore. |
| `AUTH_TOOL_DISABLED` | Il tool non e disponibile. |
| `AUTH_INVALID_RETURN_URL` | Configurazione del tool non valida. |
| `AUTH_INVALID_STATE` | Sessione di accesso non valida o scaduta. Riprova. |
| `AUTH_GOOGLE_CALLBACK_FAILED` | Accesso Google non completato. Riprova. |
| `AUTH_INVALID_GOOGLE_TOKEN` | Non e stato possibile verificare l'identita Google. |
| `AUTH_EMAIL_NOT_VERIFIED` | L'email Google non risulta verificata. |
| `AUTH_EXTERNAL_DOMAIN` | Questo servizio e riservato agli account aziendali. |
| `AUTH_USER_DISABLED` | Account non abilitato all'accesso. |
| `AUTH_NOT_AUTHORIZED_FOR_TOOL` | Account valido, ma non autorizzato per questo tool. |
| `AUTH_CODE_EXPIRED` | Sessione di accesso scaduta. Riprova. |
| `AUTH_CODE_ALREADY_USED` | Sessione di accesso gia utilizzata. Riprova. |
| `AUTH_REFRESH_TOKEN_INVALID` | Sessione non rinnovabile. Accedi di nuovo. |
| `TOOL_AUTH_FAILED` | Configurazione del tool non valida. |
| `TOKEN_IN_QUERY_REJECTED` | Token non ammesso nella query string. |
| `ADMIN_FORBIDDEN` | Non hai permessi amministrativi sufficienti. |
| `RATE_LIMITED` | Troppe richieste. Riprova piu tardi. |
| `INTERNAL_ERROR` | Errore interno. Comunica il codice di correlazione al supporto. |

## Rule

Every user-visible error page must include `correlation_id`.
