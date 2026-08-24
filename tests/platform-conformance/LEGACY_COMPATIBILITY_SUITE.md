# Legacy compatibility suite

The central Access Layer CI and each migrated project must automate the following against current consumer contracts:

- auth start accepts the current tool slug, exact return URL and state behavior;
- callback returns the current one-time code/error behavior;
- exchange preserves authentication, payload and claim semantics;
- refresh preserves rotation and activity-driven session behavior;
- introspection preserves active/inactive behavior and permission data;
- logout/revocation preserves current outcomes;
- pre-upgrade sessions, access tokens and refresh tokens work after deployment;
- legacy JWTs validate through all currently supported project integrations;
- current callback allowlists, grants and client credentials are unchanged;
- rollback remains possible within the declared window.

Use real integration harnesses for Nancy, Test Generator, Petyr, Goodman and other deployed consumers. Golden JSON alone is necessary but not sufficient.
