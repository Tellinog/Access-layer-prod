# UX.md

## User login UX

- Tool owns the protected page and starts login automatically or via button.
- Access Layer should show as little intermediate UI as possible.
- On denial, show a safe message and `correlation_id`.
- Never expose raw Google error details to the user.
- For a D-045 allowlisted tool only, `/v1/auth/start` shows one accessible intermediate choice with the target tool name and equal Google/Microsoft actions. It is not cacheable and creates no upstream auth transaction until a provider is selected.
- Non-allowlisted tools and every tool while the bridge is disabled retain the direct Google flow. Microsoft failures use generic copy plus `correlation_id` and never expose provider details.

## Admin UX

Admin UI must optimize for safe operations:

- clear tool selection;
- explicit grant status;
- confirmation for revocation and user disable;
- audit preview after sensitive changes;
- visible environment badge to avoid local/production mistakes.

## Auditor UX

Audit log search must support:

- filter by date range;
- filter by tool;
- filter by email or Google sub;
- filter by outcome/reason code;
- copy correlation ID.

## Edge cases

- User has valid Google account but no grant: show no-grant message.
- User uses personal Google account: show company-only message.
- Tool misconfigured return URL: show technical error only to tool admin; end user sees generic error.
- Google callback fails: show retry and correlation ID.

## Access request UX

Per un utente aziendale valido ma non autorizzato, mostrare un messaggio chiaro:

`Il tuo account aziendale e valido, ma non risulta autorizzato per questo tool. La richiesta e stata registrata per un amministratore. Codice: {correlation_id}.`

Non promettere approvazione automatica e non mostrare dettagli dei criteri di sicurezza.

Nella Admin UI, mostrare un badge su `Richieste accesso` quando esistono richieste pendenti visibili all'admin corrente.

## Admin session expiry UX

When an already-rendered Admin UI receives an API response indicating an invalid or expired access token, it must first attempt one same-origin activity-driven refresh and retry the original request once. If refresh fails, it must immediately replace the current page content with `Sessione scaduta. Accedi di nuovo.` and redirect to the Admin UI login route.

## Admin authenticated session UX

When the Admin UI dashboard is rendered for a valid admin session, the top bar must show the current admin identity and a `Logout` action, not a login button.

The logout action must clear the Admin UI session through the server-side logout route. `Login` is only a fallback for an already-rendered page that cannot confirm an active admin session.

## Admin input UX

Admin create/decision workflows must use inline forms instead of browser `prompt()` or `alert()` dialogs when multiple values are required.

Covered v1 flows:

- create tool;
- create grant from the grant list;
- create grant from a user detail;
- approve, reject or close access requests;
- rotate a tool client secret;
- edit tool metadata and registered permission keys;
- delete a tool after destructive confirmation.

One-time client secrets are shown in an inline result panel with a copy action and must not be shown through `alert()`.

Grant forms must use a tool select populated from the visible tool catalog and a keyboard-accessible expandable permission list with checkboxes, populated only with the selected tool's registered permission keys. The closed control reports the selection count; an empty selection remains available for role-only grants.

Desktop admin views use the full available main-content width. Forms distribute fields across responsive columns instead of being constrained to a narrow centered card; compact screens retain the single-column layout.


## Admin login gate

The Admin UI root must not render navigation, dashboard cards, tables or inline admin scripts before a valid admin session exists.

Unauthenticated visits to the Admin UI root redirect to the login route, which starts Google OAuth for the reserved `access-admin` tool.

After successful Google login and Access Layer authorization, the same root route renders the dashboard.

## Admin tool detail UX

Tool detail starts in read-only mode. `Modifica` enables metadata, Return URL and permission-key fields. Permission-key help copy explains the hierarchical `namespace:action[:scope...]` format, for example `tool:read` or `petyr:read:all`. `Salva modifiche` shows inline success or failure feedback and includes backend correlation IDs when available. `Elimina` requires explicit confirmation and then returns to the Tools list with success feedback.

Below the metadata, the detail contains the `Utenti e autorizzazioni` table. For platform admins it lists all registered users, whether access is currently effective, roles, permissions and grant states. The primary action is `Concedi grant` for a user without a grant and `Gestisci grant` for an existing grant. Delegated tool admins remain constrained by the visibility policy and see only grant targets in their assigned-tool scope.

## Admin user detail UX

The Users list has one row per registered user. The detail shows `Tool e autorizzazioni` as a table of that user's grants, with a clear `Aggiungi tool` action and a direct grant-management action on each row.

## Grant bulk import UX

Bulk grant release is designed as a guarded admin operation:

- the standard flow accepts one email per line and lets admins choose a single tool and its registered permissions from the UI;
- preview is mandatory in practice because it returns row-level validation before commit;
- commit applies no changes when any row is invalid;
- advanced CSV import remains available for mixed tool/role/action batches;
- the CSV separator may be either a comma or a semicolon and is detected from the header row;
- `pending_user_link` copy must clarify that approval already exists and the grant will activate automatically at first verified Google login.
