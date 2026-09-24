# UI_SYSTEM.md

## UI scope

V1 admin UI is functional and minimal.

Required pages:

- Dashboard
- Tools
- Tool detail
- Users
- User detail
- Grants
- Audit logs
- Settings / OAuth configuration summary
- OAuth P0 administration

The same-service v1 Admin UI implements tool and user detail as lightweight in-page views opened from the list tables.

The D-045 provider chooser is a separate, minimal legacy authentication page, not an Admin UI redesign. It contains a heading naming the escaped target tool and two keyboard-focusable links in one labelled navigation region. Existing Admin UI/Garden freeze rules remain unchanged.

The D-047 OAuth page is a same-service English-first administrative extension at `/admin/oauth`. It provides labelled forms for registration, exact redirects, explicit resource/scope mappings and allowances, credential lifecycle and signing-key lifecycle. One-time secrets appear only in a dedicated copy-now result region. Public lifecycle state remains distinct from secret output, and the temporary entitlement bridge warning is always visible.

## Layout

- Left navigation for admin areas.
- Top bar with current admin email and environment badge.
- Tables for tools, users, grants and logs.
- Detail drawers or pages for edits.
- Tool detail uses explicit `Modifica`, `Salva modifiche` and `Elimina` actions with inline feedback.
- Tool detail includes a user-access table; platform admins see registered users with effective access, while tool admins remain scoped to visible grants.
- User detail includes a tool/grant table and an `Aggiungi tool` action.
- Desktop views use the full available content width; form fields flow into responsive columns and collapse to one column only on compact screens.

## Visual direction

The Admin UI should align with the UNGUESS enterprise SaaS visual language while remaining functional and minimal:

- primary background `#FFFFFF`;
- secondary surfaces `#F7F8FA` / `#F9FAFB`;
- cards `#FFFFFF` with subtle borders `#E5E7EB` / `#EAECF0`, 16-20px radius and light shadow `0 8px 24px rgba(15,23,42,.06)`;
- main text `#101828`, secondary text `#667085`, muted text `#98A2B3`;
- primary brand petrol teal around `#004B63` / `#003F56`;
- mint accent around `#74C69D`, used sparingly for active states, positive indicators and small highlights;
- error `#EF4444`, warning `#F59E0B`;
- Inter or system sans-serif typography only.

The visual treatment must stay presentation-only unless a separate task explicitly changes behavior. Do not change routing, API calls, authentication, authorization, database behavior, environment variables or tool integration flows as part of visual alignment.

## Favicon

The Admin UI exposes a compact SVG favicon under the configured public base path. It uses the Access Layer "A" mark on the petrol-teal primary color with a mint accent, and must remain legible at 16×16 pixels.

## States

Every table needs:

- loading state;
- empty state;
- error state with correlation ID;
- pagination;
- filters.

## Accessibility

- Keyboard navigable forms.
- Labels for every input.
- Visible focus.
- Do not rely only on color for statuses.
- Permission selection uses an expandable checkbox list with a text summary of the selected count; it remains usable by keyboard and supports no selection for role-only grants.

## Status labels

| Status | Meaning |
|---|---|
| `active` | Access/configuration enabled |
| `disabled` | Disabled by admin |
| `maintenance` | Tool temporarily unavailable |
| `revoked` | Grant/session revoked |
| `expired` | Validity date passed |
| `pending_user_link` | Grant by email waiting for first verified login |

## Pagina Richieste accesso

La navigazione admin deve includere `Richieste accesso` con badge numerico delle richieste pendenti.

La tabella deve includere: stato, tool, email, nome, primo tentativo, ultimo tentativo, numero tentativi e azioni.

Azioni primarie: `Approva`, `Rifiuta`, `Chiudi`. L'azione `Approva` apre un form con ruolo, permessi, scadenza opzionale e nota.

## Inline admin forms

Admin write workflows that collect multiple fields should be rendered as minimal same-page forms with explicit labels, required browser validation where useful, one primary save action and a cancel action.

Browser `prompt()` and `alert()` dialogs are not used for tool onboarding, grant creation, access-request decisions or tool-secret rotation.

Grant forms use a single-select tool catalog and a labelled expandable permission list with checkboxes populated from the chosen tool. The list must remain keyboard navigable, show the selected-count summary and permit an empty selection for role-only grants.

## Grant bulk import UI

The Grants page includes two bulk grant controls:

- `Rilascia grant in blocco` accepts one email per line and chooses one tool, role, permissions and optional expiry from the UI;
- `Importa CSV avanzato` supports mixed bulk operations through CSV;
- `Template CSV` downloads the required import columns;
- `Export grant` downloads current grant state;
- `Export permessi` downloads registered tool permission keys;
- each bulk flow exposes `Preview` before any commit action.

Preview must show row-level `ok`, `warning` and `error` results without writing data. Commit must refuse to write when preview contains errors, then display the applied result summary.

An existing `active` or `pending_user_link` grant for the same normalized email/tool is a warning/no-op in bulk release. The existing grant stays unchanged, and repeated email/tool rows in the same input keep only the first valid row.

The input accepts both comma- and semicolon-delimited CSV files, detecting the delimiter from the required header row.
# Garden adoption status

Garden assets added by Template v2.1 are reference-only. The current embedded Admin UI styles and copy remain unchanged in Step 1. Runtime Garden integration is deferred; see `../specs/design-system.v1.yml`.
