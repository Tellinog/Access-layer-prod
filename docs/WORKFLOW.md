# WORKFLOW.md

## Workflow 1 - User requests access to a tool

1. User opens protected page on a tool.
2. Tool sees no local session.
3. Tool creates local `state` and redirects to Access Layer.
4. Access Layer logs `auth.requested`.
5. Access Layer validates tool and return URL.
6. Access Layer redirects to Google.
7. User completes Google login.
8. Access Layer validates Google ID token and domain.
9. Access Layer checks grants.
10. Access Layer logs allow/deny.
11. If allowed, Access Layer redirects to tool callback with one-time code.
12. Tool exchanges code server-to-server.
13. Tool creates local session.

## Workflow 2 - Admin grants access

1. Admin logs into Access Layer admin UI.
2. Admin opens Grants.
3. Admin selects existing user or enters company email.
4. Admin selects tool, role and permissions.
5. Access Layer writes grant.
6. Access Layer logs `admin.grant.created`.
7. User can access the tool on next login.

## Workflow 3 - User is denied

Denial can happen before or after Google login.

Before Google:

- invalid tool;
- tool disabled;
- return URL invalid.

After Google:

- invalid Google token;
- email not verified;
- missing/wrong `hd`;
- user disabled;
- no grant;
- grant expired.

Every denial must return a safe message plus correlation ID.

## Workflow 4 - Tool verifies request identity

For server-rendered apps:

1. Tool stores identity from exchange in local session.
2. On every request, tool middleware checks local session.
3. Optional: periodically introspect central token for revocation.

For API tools:

1. Client sends tool local session cookie or bearer token managed by tool.
2. Tool backend maps it to Access Layer identity.
3. Tool backend logs business action with Access Layer identity fields.

## Workflow 5 - Emergency revoke

1. Admin disables user or revokes grant.
2. Access Layer revokes active sessions for target user/tool.
3. Introspection returns inactive.
4. Tools using online check reject further requests.
5. Tools using offline JWT reject after short token TTL.

## Workflow 3 - Utente aziendale non ancora autorizzato

1. Utente apre il tool.
2. Tool redirige ad Access Layer.
3. Access Layer completa login Google e valida ID token, `email_verified` e `hd`.
4. Access Layer verifica che non esiste un grant attivo per quel tool.
5. Access Layer scrive `auth.denied.no_grant`.
6. Access Layer crea o aggiorna `access_requests` con stato `pending`.
7. Admin vede badge e riga nella sezione `Richieste accesso`.
8. Admin approva con ruolo/permessi oppure rifiuta.
9. Se approvato, Access Layer crea il grant e al successivo login l'utente accede.
