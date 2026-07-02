# Edge cases

- External account reaches callback: deny by `hd` validation.
- Email domain looks internal but `hd` missing: deny.
- User email changed: keep `google_sub`, update current email, require admin review for email-based grant conflicts.
- Tool callback code replay: deny and audit.
- Return URL with lookalike domain: deny.
- Tool disabled after auth started: deny at callback/exchange.
- Grant revoked after token issued: introspection inactive; offline JWT valid only until short TTL.
